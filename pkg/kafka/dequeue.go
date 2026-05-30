package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

// ─────────────────────────────────────────────────────────────────────────────
//  HandlerFunc — the function your service provides to process one message.
//
//  Return nil  → message is committed (success).
//  Return error → message is retried up to MaxRetries times.
//                 After all retries: sent to DLQ (if configured) or skipped.
// ─────────────────────────────────────────────────────────────────────────────

type HandlerFunc func(ctx context.Context, msg Message) error

// ─────────────────────────────────────────────────────────────────────────────
//  Consumer — reads messages from one or more Kafka topics and dispatches
//  them to registered handlers.
//
//  Usage:
//
//    c, err := kafka.NewConsumer(cfg, kafka.WithConsumerLogger(log))
//    c.Register(kafka.TopicUserRegistered, handleUserRegistered)
//    c.Register(kafka.TopicKYCApproved,    handleKYCApproved)
//    if err := c.Start(ctx); err != nil {
//        log.Error("consumer stopped", "error", err)
//    }
//
//  Start() blocks until ctx is cancelled or an unrecoverable error occurs.
//  Each registered topic gets its own goroutine + kafka.Reader.
// ─────────────────────────────────────────────────────────────────────────────

// Consumer dispatches messages from multiple topics to registered handlers.
type Consumer struct {
	cfg      Config
	handlers map[Topic]HandlerFunc
	mu       sync.Mutex
	log      *slog.Logger
	dlq      *Producer // nil if no DLQ configured
}

// NewConsumer creates a Consumer. Register topic handlers, then call Start.
func NewConsumer(cfg Config, opts ...ConsumerOption) (*Consumer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Consumer.GroupID == "" {
		return nil, fmt.Errorf("kafka/consumer: ConsumerConfig.GroupID is required")
	}

	c := &Consumer{
		cfg:      cfg,
		handlers: make(map[Topic]HandlerFunc),
		log:      slog.Default(),
	}

	for _, o := range opts {
		o(c)
	}

	// Build DLQ producer if a DLQ topic is configured
	if cfg.Consumer.DLQTopic != "" {
		dlq, err := NewProducer(cfg, WithTopics(Topic(cfg.Consumer.DLQTopic)))
		if err != nil {
			return nil, fmt.Errorf("kafka/consumer: create DLQ producer: %w", err)
		}
		c.dlq = dlq
	}

	return c, nil
}

// ConsumerOption is a functional option for NewConsumer.
type ConsumerOption func(*Consumer)

// WithConsumerLogger sets a logger for the consumer.
func WithConsumerLogger(log *slog.Logger) ConsumerOption {
	return func(c *Consumer) { c.log = log }
}

// Register binds a HandlerFunc to a topic.
// Must be called before Start.
// Calling Register after Start has no effect on the running consumer.
func (c *Consumer) Register(topic Topic, handler HandlerFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[topic] = handler
}

// Start launches one goroutine per registered topic and blocks until ctx
// is cancelled. All goroutines are waited on before Start returns.
//
// Returns nil on clean shutdown (ctx cancelled).
// Returns an error if a topic worker encounters an unrecoverable error.
func (c *Consumer) Start(ctx context.Context) error {
	c.mu.Lock()
	handlers := make(map[Topic]HandlerFunc, len(c.handlers))
	for t, h := range c.handlers {
		handlers[t] = h
	}
	c.mu.Unlock()

	if len(handlers) == 0 {
		return fmt.Errorf("kafka/consumer: no topics registered — call Register() before Start()")
	}

	errs := make(chan error, len(handlers))
	var wg sync.WaitGroup

	for topic, handler := range handlers {
		wg.Add(1)
		go func(t Topic, h HandlerFunc) {
			defer wg.Done()
			c.log.Info("topic worker starting", "topic", t, "group", c.cfg.Consumer.GroupID)
			if err := c.runWorker(ctx, t, h); err != nil {
				errs <- fmt.Errorf("topic %s: %w", t, err)
			}
		}(topic, handler)
	}

	// Wait for all workers to stop, then close the error channel
	go func() {
		wg.Wait()
		close(errs)
	}()

	// Return the first non-nil error (if any)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// ─── Worker (one per topic) ───────────────────────────────────────────────────

func (c *Consumer) runWorker(ctx context.Context, topic Topic, handler HandlerFunc) error {
	dialer, err := c.cfg.dialer()
	if err != nil {
		return fmt.Errorf("build dialer: %w", err)
	}

	cc := c.cfg.Consumer
	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:        c.cfg.Brokers,
		Topic:          string(topic),
		GroupID:        cc.GroupID,
		MinBytes:       cc.MinBytes,
		MaxBytes:       cc.MaxBytes,
		CommitInterval: cc.CommitInterval, // 0 = manual commit
		StartOffset:    cc.StartOffset,
		Dialer:         dialer,
		ErrorLogger: kafkago.LoggerFunc(func(msg string, a ...interface{}) {
			c.log.Error("kafka reader", "topic", topic, "msg", fmt.Sprintf(msg, a...))
		}),
	})
	defer reader.Close()

	for {
		// FetchMessage blocks until a message is available or ctx is cancelled.
		// It does NOT commit the offset — we commit manually after success.
		raw, err := reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				c.log.Info("worker stopping cleanly", "topic", topic)
				return nil
			}
			// Transient error (e.g. broker restart) — log and retry fetch
			c.log.Warn("fetch error — retrying", "topic", topic, "error", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		msg := rawToMessage(raw)

		if err := c.dispatch(ctx, topic, msg, handler); err != nil {
			// dispatch already handled retries and DLQ.
			// Log and continue — don't let one bad message stop the worker.
			c.log.Error("message permanently failed",
				"topic", topic,
				"partition", raw.Partition,
				"offset", raw.Offset,
				"error", err,
			)
		}

		// Commit the offset regardless of handler outcome.
		// This advances our position so we don't reprocess this message on restart.
		if err := reader.CommitMessages(ctx, raw); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			c.log.Error("commit offset failed", "topic", topic, "offset", raw.Offset, "error", err)
		}
	}
}

// ─── Dispatch with retry + DLQ ────────────────────────────────────────────────

func (c *Consumer) dispatch(ctx context.Context, topic Topic, msg Message, handler HandlerFunc) error {
	cc := c.cfg.Consumer
	maxRetries := cc.MaxRetries
	if maxRetries < 1 {
		maxRetries = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := c.callHandler(ctx, handler, msg)
		if err == nil {
			if attempt > 1 {
				c.log.Info("message succeeded after retry",
					"topic", topic,
					"attempt", attempt,
					"offset", msg.Offset,
				)
			}
			return nil
		}

		lastErr = err
		c.log.Warn("handler error",
			"topic", topic,
			"attempt", attempt,
			"max_retries", maxRetries,
			"offset", msg.Offset,
			"error", err,
		)

		if attempt < maxRetries {
			backoff := cc.RetryBackoff * time.Duration(attempt) // linear backoff: 100ms, 200ms, 300ms
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// All retries exhausted — send to DLQ or log and skip
	c.log.Error("all retries exhausted",
		"topic", topic,
		"offset", msg.Offset,
		"final_error", lastErr,
	)

	if c.dlq != nil {
		if dlqErr := c.sendToDLQ(ctx, topic, msg, lastErr); dlqErr != nil {
			c.log.Error("DLQ publish failed", "error", dlqErr)
		}
	}

	return fmt.Errorf("all %d retries failed: %w", maxRetries, lastErr)
}

// callHandler invokes the handler and recovers from panics.
func (c *Consumer) callHandler(ctx context.Context, handler HandlerFunc, msg Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panicked: %v", r)
		}
	}()
	return handler(ctx, msg)
}

// sendToDLQ publishes a failed message to the dead-letter queue topic.
// The DLQ message contains the original payload + error metadata as headers.
func (c *Consumer) sendToDLQ(ctx context.Context, sourceTopic Topic, msg Message, originalErr error) error {
	headers := append(msg.Headers,
		Header{Key: "dlq-source-topic", Value: []byte(sourceTopic)},
		Header{Key: "dlq-error", Value: []byte(originalErr.Error())},
		Header{Key: "dlq-timestamp", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
	)

	return c.dlq.EnqueueRaw(ctx, Message{
		Topic:   Topic(c.cfg.Consumer.DLQTopic),
		Key:     msg.Key,
		Value:   msg.Value,
		Headers: headers,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
//  Decode helper — unmarshal a Message's Value into your event struct.
//
//  Usage inside a HandlerFunc:
//
//    var event events.UserRegisteredEvent
//    if err := kafka.Decode(msg, &event); err != nil {
//        return err  // will trigger retry
//    }
// ─────────────────────────────────────────────────────────────────────────────

// Decode unmarshals a Message's JSON Value into out.
func Decode[T any](msg Message, out *T) error {
	if err := json.Unmarshal(msg.Value, out); err != nil {
		return fmt.Errorf("kafka/decode: unmarshal from topic %s: %w", msg.Topic, err)
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func rawToMessage(raw kafkago.Message) Message {
	headers := make([]Header, len(raw.Headers))
	for i, h := range raw.Headers {
		headers[i] = Header{Key: h.Key, Value: h.Value}
	}
	return Message{
		Topic:     Topic(raw.Topic),
		Key:       raw.Key,
		Value:     raw.Value,
		Headers:   headers,
		Partition: raw.Partition,
		Offset:    raw.Offset,
		Time:      raw.Time,
	}
}
