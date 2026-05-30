package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// ─────────────────────────────────────────────────────────────────────────────
//  Config — top-level config for both producer and consumer.
//  Pass this to NewProducer and NewConsumer.
// ─────────────────────────────────────────────────────────────────────────────

// Config is everything needed to connect to a Kafka/Redpanda broker.
type Config struct {
	// Brokers is a list of bootstrap broker addresses.
	// Local dev:        []string{"localhost:9092"}
	// Redpanda Cloud:   []string{"seed-xxxx.cloud.redpanda.com:9092"}
	// Multiple brokers: []string{"b1:9092", "b2:9092"}  ← for resilience
	Brokers []string

	// ClientID identifies this application in the broker's connection log.
	// Use your service name: "sentinel", "wallet-service", etc.
	// Shows up in Redpanda Console → Brokers → Connections.
	ClientID string

	// TLS — nil means no TLS (local dev).
	// Redpanda Cloud requires TLS.
	TLS *TLSConfig

	// SASL — nil means no authentication (local dev).
	// Redpanda Cloud requires SASL/SCRAM-SHA-256.
	SASL *SASLConfig

	// Producer config — only used by NewProducer.
	Producer ProducerConfig

	// Consumer config — only used by NewConsumer.
	Consumer ConsumerConfig
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

// TLSConfig configures TLS encryption for the broker connection.
type TLSConfig struct {
	// Enabled must be true to activate TLS.
	Enabled bool

	// InsecureSkipVerify skips certificate verification.
	// OK for local dev with self-signed certs. NEVER use in production.
	InsecureSkipVerify bool

	// CertFile + KeyFile — path to client cert/key for mutual TLS.
	// Leave empty if the broker doesn't require client certificates.
	CertFile string
	KeyFile  string

	// CAFile — path to custom CA certificate PEM file.
	// Required when your broker uses a private CA (e.g. self-hosted Redpanda).
	// Leave empty to use system CAs (works for Redpanda Cloud).
	CAFile string
}

// build converts TLSConfig into a *tls.Config for kafka-go.
func (t *TLSConfig) build() (*tls.Config, error) {
	if t == nil || !t.Enabled {
		return nil, nil
	}

	cfg := &tls.Config{
		InsecureSkipVerify: t.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	// Load custom CA if provided
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("kafka/tls: read CA file %q: %w", t.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kafka/tls: failed to parse CA cert from %q", t.CAFile)
		}
		cfg.RootCAs = pool
	}

	// Load client certificate if provided (mutual TLS)
	if t.CertFile != "" && t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("kafka/tls: load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// ─── SASL ─────────────────────────────────────────────────────────────────────

// SASLMechanism is the authentication mechanism type.
type SASLMechanism string

const (
	SASLPlain       SASLMechanism = "PLAIN"
	SASLScramSHA256 SASLMechanism = "SCRAM-SHA-256" // Redpanda Cloud default
	SASLScramSHA512 SASLMechanism = "SCRAM-SHA-512"
)

// SASLConfig configures SASL authentication.
type SASLConfig struct {
	Mechanism SASLMechanism
	Username  string
	Password  string
}

// build converts SASLConfig into a kafka-go sasl.Mechanism.
func (s *SASLConfig) build() (sasl.Mechanism, error) {
	if s == nil {
		return nil, nil
	}
	if s.Username == "" || s.Password == "" {
		return nil, fmt.Errorf("kafka/sasl: username and password are required")
	}

	switch s.Mechanism {
	case SASLPlain:
		return plain.Mechanism{
			Username: s.Username,
			Password: s.Password,
		}, nil

	case SASLScramSHA256:
		m, err := scram.Mechanism(scram.SHA256, s.Username, s.Password)
		if err != nil {
			return nil, fmt.Errorf("kafka/sasl: create SCRAM-SHA-256 mechanism: %w", err)
		}
		return m, nil

	case SASLScramSHA512:
		m, err := scram.Mechanism(scram.SHA512, s.Username, s.Password)
		if err != nil {
			return nil, fmt.Errorf("kafka/sasl: create SCRAM-SHA-512 mechanism: %w", err)
		}
		return m, nil

	default:
		return nil, fmt.Errorf("kafka/sasl: unknown mechanism %q (use PLAIN, SCRAM-SHA-256, or SCRAM-SHA-512)", s.Mechanism)
	}
}

// ─── Producer Config ──────────────────────────────────────────────────────────

// ProducerConfig tunes how messages are sent to the broker.
type ProducerConfig struct {
	// RequiredAcks controls durability vs latency.
	//
	//   RequireNone (-1) → fire-and-forget. Fastest, no durability guarantee.
	//   RequireOne  (1)  → leader confirms write. Good default. (DEFAULT)
	//   RequireAll  (-1) → all in-sync replicas confirm. Slowest, most durable.
	//                      Only meaningful if you have replication factor > 1.
	RequiredAcks kafkago.RequiredAcks

	// BatchSize is the max number of messages to accumulate before sending.
	// Larger batches = better throughput, higher latency.
	// Default: 100
	BatchSize int

	// BatchTimeout is how long to wait for a batch to fill before flushing.
	// Lower = lower latency. Higher = better throughput.
	// Default: 10ms
	BatchTimeout time.Duration

	// MaxAttempts is how many times to retry a failed write (network errors etc).
	// Default: 3
	MaxAttempts int

	// WriteTimeout is the deadline for a single write attempt to the broker.
	// Default: 10s
	WriteTimeout time.Duration

	// Compression algorithm.
	// None=0, Gzip=1, Snappy=2, Lz4=3, Zstd=4
	// Snappy is a good default — fast with decent compression.
	Compression kafkago.Compression
}

// ─── Consumer Config ──────────────────────────────────────────────────────────

// ConsumerConfig tunes how messages are received and processed.
type ConsumerConfig struct {
	// GroupID is the consumer group this instance belongs to.
	// All instances with the same GroupID share partitions.
	// Each service uses a unique GroupID (see topic.go for constants).
	GroupID string

	// StartOffset determines where to start reading when no committed
	// offset exists for this group (i.e. first time the group runs).
	//
	//   kafkago.FirstOffset → read from the beginning of the topic
	//   kafkago.LastOffset  → only read messages produced after startup
	//
	// Default: kafkago.FirstOffset
	StartOffset int64

	// MinBytes is the minimum bytes to fetch per request.
	// 1 = return as soon as any message is available (low latency).
	// Default: 1
	MinBytes int

	// MaxBytes is the maximum bytes to fetch per request.
	// Default: 1MB
	MaxBytes int

	// MaxRetries is how many times a failing handler is retried per message.
	// After MaxRetries, the message is sent to DLQTopic (if set) or skipped.
	// Default: 3
	MaxRetries int

	// RetryBackoff is the base duration for exponential backoff between retries.
	// Retry 1: RetryBackoff × 1
	// Retry 2: RetryBackoff × 2
	// Retry 3: RetryBackoff × 4
	// Default: 100ms
	RetryBackoff time.Duration

	// CommitInterval is how often offsets are auto-committed to the broker.
	// 0 = manual commit (default, used by runWorker via CommitMessages).
	CommitInterval time.Duration

	// DLQTopic is the dead-letter queue topic name.
	// Messages that exhaust all retries are published here for later inspection.
	// Leave empty to just log and skip failed messages.
	DLQTopic string
}

// ─── Defaults ─────────────────────────────────────────────────────────────────

// DefaultConfig returns a ready-to-use Config for local development.
// Override only the fields you need to change.
//
// Example:
//
//	cfg := kafka.DefaultConfig([]string{"localhost:9092"}, "sentinel")
//	cfg.Consumer.GroupID = kafka.GroupAuthService
//	cfg.Consumer.DLQTopic = "auth.dlq"
func DefaultConfig(brokers []string, clientID string) Config {
	return Config{
		Brokers:  brokers,
		ClientID: clientID,
		Producer: ProducerConfig{
			RequiredAcks: kafkago.RequireOne,
			BatchSize:    100,
			BatchTimeout: 10 * time.Millisecond,
			MaxAttempts:  3,
			WriteTimeout: 10 * time.Second,
			Compression:  kafkago.Snappy,
		},
		Consumer: ConsumerConfig{
			StartOffset:  kafkago.FirstOffset,
			MinBytes:     1,
			MaxBytes:     1_000_000,
			MaxRetries:   3,
			RetryBackoff: 100 * time.Millisecond,
		},
	}
}

// RedpandaCloudConfig returns a Config pre-configured for Redpanda Cloud.
// Fill in the brokerURL, username, password from your cloud dashboard.
//
// Example:
//
//	cfg := kafka.RedpandaCloudConfig(
//	    "seed-abc123.cloud.redpanda.com:9092",
//	    os.Getenv("REDPANDA_USERNAME"),
//	    os.Getenv("REDPANDA_PASSWORD"),
//	    "sentinel",
//	)
func RedpandaCloudConfig(brokerURL, username, password, clientID string) Config {
	cfg := DefaultConfig([]string{brokerURL}, clientID)
	cfg.TLS = &TLSConfig{Enabled: true} // Redpanda Cloud uses system CAs — no CAFile needed
	cfg.SASL = &SASLConfig{
		Mechanism: SASLScramSHA256,
		Username:  username,
		Password:  password,
	}
	return cfg
}

// ─── Validation ───────────────────────────────────────────────────────────────

// Validate returns an error if the config is missing required fields.
func (c *Config) Validate() error {
	if len(c.Brokers) == 0 {
		return fmt.Errorf("kafka: at least one broker address is required")
	}
	for i, b := range c.Brokers {
		if b == "" {
			return fmt.Errorf("kafka: broker[%d] is empty", i)
		}
	}
	if c.ClientID == "" {
		return fmt.Errorf("kafka: ClientID is required — use your service name")
	}
	return nil
}

// ─── Internal: build a Dialer ─────────────────────────────────────────────────

// dialer builds a kafka-go Dialer with TLS and SASL applied.
// Used internally by Admin (topic.go) and Consumer readers.
func (c *Config) dialer() (*kafkago.Dialer, error) {
	tlsCfg, err := c.TLS.build()
	if err != nil {
		return nil, err
	}

	saslMech, err := c.SASL.build()
	if err != nil {
		return nil, err
	}

	return &kafkago.Dialer{
		Timeout:       10 * time.Second,
		DualStack:     true,
		ClientID:      c.ClientID,
		TLS:           tlsCfg,
		SASLMechanism: saslMech,
	}, nil
}

// transport builds a kafka-go Transport for use with Writer (Producer).
// Writers in kafka-go v0.4+ use Transport instead of Dialer.
func (c *Config) transport() (*kafkago.Transport, error) {
	tlsCfg, err := c.TLS.build()
	if err != nil {
		return nil, err
	}

	saslMech, err := c.SASL.build()
	if err != nil {
		return nil, err
	}

	return &kafkago.Transport{
		TLS:  tlsCfg,
		SASL: saslMech,
	}, nil
}
