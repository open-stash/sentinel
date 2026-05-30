package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

// ─────────────────────────────────────────────────────────────────────────────
//  Message — the unit of data sent to / received from Kafka.
// ─────────────────────────────────────────────────────────────────────────────

// Message carries a single Kafka record.
type Message struct {
	// Topic to send this message to (used in EnqueueBatch).
	Topic Topic

	// Key is the partition routing key.
	// Messages with the same key always go to the same partition → ordering.
	// Set to user_id for user events, symbol for trade events.
	// Leave nil for unkeyed (round-robin) routing.
	Key []byte

	// Value is the raw payload bytes.
	Value []byte

	// Headers are optional metadata — visible without parsing Value.
	// Useful for routing, filtering, and tracing.
	Headers []Header

	// These are set on messages received from the broker (read-only).
	Partition int
	Offset    int64
	Time      time.Time
}

// Header is a key-value pair attached to a message.
type Header struct {
	Key   string
	Value []byte
}

// ─────────────────────────────────────────────────────────────────────────────
//  Producer — sends messages to Redpanda/Kafka.
//
//  Create once at startup, reuse across goroutines (it is safe for concurrent use).
//  Always call Close() on shutdown.
//
//  Usage:
//
//    p, err := kafka.NewProducer(cfg)
//    if err != nil { ... }
//    defer p.Close()
//
//    // Publish a JSON event (most common)
//    err = p.Enqueue(ctx, kafka.TopicUserRegistered, userID, event)
//
//    // Publish multiple messages in one broker round-trip
//    err = p.EnqueueBatch(ctx, msgs)
// ─────────────────────────────────────────────────────────────────────────────

// Producer publishes messages to Kafka/Redpanda.
type Producer struct {
	writers map[Topic]*kafkago.Writer
	mu      sync.RWMutex // protects writers map
	cfg     Config
	log     *slog.Logger
}

// NewProducer creates a Producer.
// It creates one internal writer per topic listed in topics.
// If you try to publish to an unlisted topic, Enqueue returns an error.
//
// Example:
//
//	p, err := kafka.NewProducer(cfg,
//	    kafka.WithLogger(log),
//	    kafka.WithTopics(
//	        kafka.TopicUserRegistered,
//	        kafka.TopicUserLogin,
//	    ),
//	)
func NewProducer(cfg Config, opts ...ProducerOption) (*Producer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p := &Producer{
		writers: make(map[Topic]*kafkago.Writer),
		cfg:     cfg,
		log:     slog.Default(),
	}

	for _, o := range opts {
		o(p)
	}

	return p, nil
}

// ProducerOption is a functional option for NewProducer.
type ProducerOption func(*Producer)

// WithLogger sets the logger for the producer.
func WithLogger(log *slog.Logger) ProducerOption {
	return func(p *Producer) { p.log = log }
}

// WithTopics pre-registers topics so writers are created eagerly.
// Optional — writers are also created lazily on first Enqueue call.
func WithTopics(topics ...Topic) ProducerOption {
	return func(p *Producer) {
		for _, t := range topics {
			p.writerFor(t) // nolint:errcheck — creates writer, ignores error
		}
	}
}

// ─── Enqueue variants ─────────────────────────────────────────────────────────

// Enqueue serialises value as JSON and publishes it to topic.
//
// key is the partition routing key — use user_id, symbol, order_id etc.
// to ensure related messages go to the same partition (ordering guarantee).
// Pass "" for round-robin partition assignment.
//
// This is the method you'll call 95% of the time.
func (p *Producer) Enqueue(ctx context.Context, topic Topic, key string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("kafka/enqueue: marshal value for topic %s: %w", topic, err)
	}

	return p.EnqueueRaw(ctx, Message{
		Topic: topic,
		Key:   strToBytes(key),
		Value: payload,
	})
}

// EnqueueWithHeaders is like Enqueue but lets you attach metadata headers.
// Headers are visible to consumers without parsing the Value payload —
// useful for routing decisions and distributed tracing (e.g. trace-id).
func (p *Producer) EnqueueWithHeaders(ctx context.Context, topic Topic, key string, value any, headers ...Header) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("kafka/enqueue: marshal value for topic %s: %w", topic, err)
	}

	return p.EnqueueRaw(ctx, Message{
		Topic:   topic,
		Key:     strToBytes(key),
		Value:   payload,
		Headers: headers,
	})
}

// EnqueueRaw publishes a pre-built Message with raw bytes.
// Use when you don't want JSON encoding (e.g. Protobuf, Avro, raw string).
func (p *Producer) EnqueueRaw(ctx context.Context, msg Message) error {
	w, err := p.writerFor(msg.Topic)
	if err != nil {
		return err
	}

	km := kafkago.Message{
		Key:   msg.Key,
		Value: msg.Value,
	}
	for _, h := range msg.Headers {
		km.Headers = append(km.Headers, kafkago.Header{
			Key:   h.Key,
			Value: h.Value,
		})
	}

	start := time.Now()
	if err := w.WriteMessages(ctx, km); err != nil {
		return fmt.Errorf("kafka/enqueue: write to topic %s: %w", msg.Topic, err)
	}

	p.log.Debug("message enqueued",
		"topic", msg.Topic,
		"key", string(msg.Key),
		"bytes", len(msg.Value),
		"latency_ms", time.Since(start).Milliseconds(),
	)
	return nil
}

// EnqueueBatch publishes multiple messages in a single broker round-trip.
// Messages can target different topics — they are grouped internally per topic.
//
// All messages succeed or fail atomically per topic (not across topics).
// If you need cross-topic atomicity you need Kafka transactions (out of scope here).
//
// Use for:
//   - Bulk imports
//   - Fan-out: same event to multiple topics
//   - Throughput-critical paths where individual Enqueue is too slow
func (p *Producer) EnqueueBatch(ctx context.Context, msgs []Message) error {
	if len(msgs) == 0 {
		return nil
	}

	// Group messages by topic
	byTopic := make(map[Topic][]kafkago.Message, len(msgs))
	for _, m := range msgs {
		km := kafkago.Message{
			Key:   m.Key,
			Value: m.Value,
		}
		for _, h := range m.Headers {
			km.Headers = append(km.Headers, kafkago.Header{Key: h.Key, Value: h.Value})
		}
		byTopic[m.Topic] = append(byTopic[m.Topic], km)
	}

	// Write each topic's batch
	for topic, kMsgs := range byTopic {
		w, err := p.writerFor(topic)
		if err != nil {
			return err
		}
		if err := w.WriteMessages(ctx, kMsgs...); err != nil {
			return fmt.Errorf("kafka/enqueue batch: write to topic %s: %w", topic, err)
		}
	}

	p.log.Debug("batch enqueued", "total_messages", len(msgs), "topics", len(byTopic))
	return nil
}

// Close flushes buffered messages and closes all writers.
// Must be called on service shutdown — unflushed messages are lost otherwise.
func (p *Producer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for topic, w := range p.writers {
		if err := w.Close(); err != nil {
			p.log.Error("close kafka writer failed", "topic", topic, "error", err)
			lastErr = err
		}
	}
	return lastErr
}

// Stats returns write statistics for a topic — useful for monitoring.
func (p *Producer) Stats(topic Topic) (kafkago.WriterStats, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	w, ok := p.writers[topic]
	if !ok {
		return kafkago.WriterStats{}, false
	}
	return w.Stats(), true
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// writerFor returns (or lazily creates) a kafka.Writer for the given topic.
func (p *Producer) writerFor(topic Topic) (*kafkago.Writer, error) {
	// Fast path: writer already exists
	p.mu.RLock()
	if w, ok := p.writers[topic]; ok {
		p.mu.RUnlock()
		return w, nil
	}
	p.mu.RUnlock()

	// Slow path: create writer
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if w, ok := p.writers[topic]; ok {
		return w, nil
	}

	transport, err := p.cfg.transport()
	if err != nil {
		return nil, fmt.Errorf("kafka/producer: build transport: %w", err)
	}

	pc := p.cfg.Producer
	w := &kafkago.Writer{
		Addr:         kafkago.TCP(p.cfg.Brokers...),
		Topic:        string(topic),
		Balancer:     &kafkago.Hash{}, // Hash balancer uses Key for partition routing
		Transport:    transport,
		RequiredAcks: pc.RequiredAcks,
		BatchSize:    pc.BatchSize,
		BatchTimeout: pc.BatchTimeout,
		MaxAttempts:  pc.MaxAttempts,
		WriteTimeout: pc.WriteTimeout,
		Compression:  pc.Compression,
		ErrorLogger: kafkago.LoggerFunc(func(msg string, a ...interface{}) {
			p.log.Error("kafka writer", "topic", topic, "msg", fmt.Sprintf(msg, a...))
		}),
	}

	p.writers[topic] = w
	p.log.Debug("kafka writer created", "topic", topic)
	return w, nil
}

func strToBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}
