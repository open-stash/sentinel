// Package mq provides the RabbitMQ publisher that emits notification events to
// beacon (the email worker). Sentinel is publish-only — it declares the exchange
// and pushes {type, payload} envelopes; beacon owns the queue and bindings.
package mq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/open-stash/sentinel/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

// envelope is the message contract beacon consumes: {type, payload}.
type envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// Publisher emits notification events to beacon via a RabbitMQ exchange.
type Publisher struct {
	conn       *amqp.Connection
	ch         *amqp.Channel
	exchange   string
	routingKey string
}

// NewPublisher dials RabbitMQ and declares the (durable) notification exchange.
func NewPublisher(cfg config.RabbitMQConfig) (*Publisher, error) {
	conn, err := dial(cfg.BrokerURL)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open channel: %w", err)
	}
	if err := ch.ExchangeDeclare(
		cfg.ExchangeName, cfg.ExchangeType,
		true, false, false, false, nil,
	); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("declare exchange %q: %w", cfg.ExchangeName, err)
	}
	return &Publisher{
		conn:       conn,
		ch:         ch,
		exchange:   cfg.ExchangeName,
		routingKey: cfg.RoutingKey,
	}, nil
}

func dial(url string) (*amqp.Connection, error) {
	var lastErr error
	for i := range 5 {
		conn, err := amqp.Dial(url)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		log.Printf("rabbitmq connection attempt %d failed: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("connect rabbitmq after 5 attempts: %w", lastErr)
}

// Publish marshals payload into the {type, payload} envelope and publishes it to
// the configured exchange + routing key. Satisfies service.Notifier.
func (p *Publisher) Publish(ctx context.Context, eventType string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	msg, err := json.Marshal(envelope{Type: eventType, Payload: body})
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return p.ch.PublishWithContext(ctx, p.exchange, p.routingKey, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Timestamp:    time.Now(),
		Body:         msg,
	})
}

// Close releases the channel and connection.
func (p *Publisher) Close() error {
	var err error
	if p.ch != nil {
		err = errors.Join(err, p.ch.Close())
	}
	if p.conn != nil {
		err = errors.Join(err, p.conn.Close())
	}
	return err
}
