package service

import "context"

// Notifier publishes notification events to the message broker. They are consumed
// by beacon (the email worker), which renders and sends the matching email.
// Implemented by pkg/mq.Publisher.
type Notifier interface {
	Publish(ctx context.Context, eventType string, payload any) error
}
