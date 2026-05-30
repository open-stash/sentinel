package kafka

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

// ─────────────────────────────────────────────────────────────────────────────
//  Topic names — single source of truth.
//  Every service imports this package, nobody hardcodes strings.
// ─────────────────────────────────────────────────────────────────────────────

// Topic is a typed string for topic names.
// Prevents passing arbitrary strings where a topic name is expected.
type Topic string

// Auth Service topics
const (
	TopicUserRegistered      Topic = "user.registered"
	TopicUserLogin           Topic = "user.login"
	TopicUserEmailVerified   Topic = "user.email_verified"
	TopicUserPasswordChanged Topic = "user.password_changed"
	TopicUserLogout          Topic = "user.logout"
)

// KYC Service topics
const (
	TopicKYCSubmitted Topic = "kyc.submitted"
	TopicKYCApproved  Topic = "kyc.approved"
	TopicKYCRejected  Topic = "kyc.rejected"
)

// Wallet Service topics
const (
	TopicBalanceCredited     Topic = "balance.credited"
	TopicBalanceDebited      Topic = "balance.debited"
	TopicWithdrawalQueued    Topic = "withdrawal.queued"
	TopicWithdrawalProcessed Topic = "withdrawal.processed"
	TopicWithdrawalFailed    Topic = "withdrawal.failed"
)

// Order Service topics
const (
	TopicOrderPlaced    Topic = "order.placed"
	TopicOrderCancelled Topic = "order.cancelled"
	TopicOrderUpdated   Topic = "order.updated"
)

// Matching Engine topics
const (
	// TopicTradeFilled is the highest-volume topic in the exchange.
	// Partition key = trading symbol (e.g. "BTC-USD") so all trades
	// for a symbol arrive in order at the Market Data Service.
	TopicTradeFilled Topic = "trade.filled"
)

// Notification Service topics
const (
	TopicNotificationSend Topic = "notification.send"
)

// ─────────────────────────────────────────────────────────────────────────────
//  Consumer Group IDs — each service uses a unique ID so Redpanda tracks
//  their offsets independently and they each receive all messages.
// ─────────────────────────────────────────────────────────────────────────────

const (
	GroupAuthService         = "sentinel"
	GroupWalletService       = "wallet-service"
	GroupKYCService          = "kyc-service"
	GroupOrderService        = "order-service"
	GroupFeeService          = "fee-service"
	GroupMarketDataService   = "market-data-service"
	GroupNotificationService = "notification-service"
	GroupAnalyticsService    = "analytics-service"
	GroupSecurityService     = "security-service"
)

// ─────────────────────────────────────────────────────────────────────────────
//  TopicConfig — defines how a topic is created.
// ─────────────────────────────────────────────────────────────────────────────

// TopicConfig defines the settings for creating a Kafka topic.
type TopicConfig struct {
	// Name of the topic.
	Name Topic

	// NumPartitions controls parallelism.
	// More partitions = more consumers can read in parallel.
	// Rule of thumb: num_partitions >= expected_peak_consumers
	// Low-volume (user events):    3
	// Medium-volume (orders):      6
	// High-volume (trade.filled): 12
	NumPartitions int

	// ReplicationFactor: how many broker copies.
	// 1 = no replication (fine for dev, data loss risk in prod)
	// 3 = standard prod (need 3+ brokers)
	ReplicationFactor int

	// RetentionMs: how long messages are kept.
	// Use the Retention* constants below.
	// Default: 7 days
	RetentionMs int64

	// CleanupPolicy: "delete" (default) removes old messages by time/size.
	// "compact" keeps only the latest message per key (good for state topics).
	CleanupPolicy string
}

// Retention duration constants — use these instead of raw millisecond values.
const (
	Retention1Hour   int64 = 3_600_000
	Retention6Hours  int64 = 21_600_000
	Retention1Day    int64 = 86_400_000
	Retention7Days   int64 = 604_800_000  // default
	Retention30Days  int64 = 2_592_000_000
	RetentionForever int64 = -1
)

// ExchangeTopics returns the TopicConfig for every topic in the exchange.
// Pass this to Admin.EnsureTopics to create them all at startup.
//
// Usage:
//
//	admin, _ := kafka.NewAdmin(ctx, cfg)
//	admin.EnsureTopics(ctx, kafka.ExchangeTopics())
func ExchangeTopics() []TopicConfig {
	return []TopicConfig{
		// ── Auth Service ─────────────────────────────────────────────────────
		{Name: TopicUserRegistered, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicUserLogin, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention7Days},
		{Name: TopicUserEmailVerified, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicUserPasswordChanged, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicUserLogout, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention1Day},

		// ── KYC Service ──────────────────────────────────────────────────────
		{Name: TopicKYCSubmitted, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicKYCApproved, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicKYCRejected, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention30Days},

		// ── Wallet Service ───────────────────────────────────────────────────
		{Name: TopicBalanceCredited, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicBalanceDebited, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicWithdrawalQueued, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicWithdrawalProcessed, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicWithdrawalFailed, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},

		// ── Order Service ────────────────────────────────────────────────────
		{Name: TopicOrderPlaced, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicOrderCancelled, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},
		{Name: TopicOrderUpdated, NumPartitions: 6, ReplicationFactor: 1, RetentionMs: Retention30Days},

		// ── Matching Engine ──────────────────────────────────────────────────
		// 12 partitions: partition key = symbol → all BTC-USD trades in order
		{Name: TopicTradeFilled, NumPartitions: 12, ReplicationFactor: 1, RetentionMs: Retention30Days},

		// ── Notification ─────────────────────────────────────────────────────
		{Name: TopicNotificationSend, NumPartitions: 3, ReplicationFactor: 1, RetentionMs: Retention1Day},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
//  Admin — creates and manages topics.
// ─────────────────────────────────────────────────────────────────────────────

// Admin manages topics on the Kafka/Redpanda broker.
// Typically used once at service startup to ensure required topics exist.
type Admin struct {
	conn    *kafkago.Conn
	brokers []string
}

// NewAdmin creates an Admin client.
// It connects to the broker and finds the controller (leader) node.
func NewAdmin(ctx context.Context, cfg Config) (*Admin, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	dialer, err := cfg.dialer()
	if err != nil {
		return nil, err
	}

	// Connect to the first broker to discover the controller
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Brokers[0])
	if err != nil {
		return nil, fmt.Errorf("kafka/admin: connect to %s: %w", cfg.Brokers[0], err)
	}

	// Topics must be created on the controller node
	controller, err := conn.Controller()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("kafka/admin: get controller: %w", err)
	}
	conn.Close()

	controllerAddr := net.JoinHostPort(controller.Host, fmt.Sprint(controller.Port))
	leaderConn, err := dialer.DialContext(ctx, "tcp", controllerAddr)
	if err != nil {
		return nil, fmt.Errorf("kafka/admin: connect to controller %s: %w", controllerAddr, err)
	}

	return &Admin{conn: leaderConn, brokers: cfg.Brokers}, nil
}

// EnsureTopics creates topics that don't yet exist.
// Topics that already exist are silently skipped — safe to call on every startup.
//
// Example at service startup:
//
//	admin, err := kafka.NewAdmin(ctx, cfg)
//	if err != nil { log.Fatal(err) }
//	defer admin.Close()
//	if err := admin.EnsureTopics(ctx, kafka.ExchangeTopics()); err != nil {
//	    log.Fatal(err)
//	}
func (a *Admin) EnsureTopics(ctx context.Context, topics []TopicConfig) error {
	specs := make([]kafkago.TopicConfig, 0, len(topics))
	for _, t := range topics {
		retention := t.RetentionMs
		if retention == 0 {
			retention = Retention7Days
		}
		policy := t.CleanupPolicy
		if policy == "" {
			policy = "delete"
		}
		rf := t.ReplicationFactor
		if rf == 0 {
			rf = 1
		}

		specs = append(specs, kafkago.TopicConfig{
			Topic:             string(t.Name),
			NumPartitions:     t.NumPartitions,
			ReplicationFactor: rf,
			ConfigEntries: []kafkago.ConfigEntry{
				{ConfigName: "retention.ms", ConfigValue: fmt.Sprint(retention)},
				{ConfigName: "cleanup.policy", ConfigValue: policy},
			},
		})
	}

	if err := a.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return fmt.Errorf("kafka/admin: set deadline: %w", err)
	}

	if err := a.conn.CreateTopics(specs...); err != nil {
		// kafka-go returns an error that wraps individual topic errors.
		// Redpanda returns TopicAlreadyExists for existing topics — ignore it.
		return filterTopicAlreadyExists(err)
	}

	return nil
}

// CreateTopic creates a single topic. Skips if it already exists.
func (a *Admin) CreateTopic(ctx context.Context, topic TopicConfig) error {
	return a.EnsureTopics(ctx, []TopicConfig{topic})
}

// DeleteTopic deletes a topic and all its data. Irreversible.
func (a *Admin) DeleteTopic(ctx context.Context, name Topic) error {
	if err := a.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	return a.conn.DeleteTopics(string(name))
}

// ListTopics returns the names of all topics on the broker.
func (a *Admin) ListTopics(ctx context.Context) ([]string, error) {
	partitions, err := a.conn.ReadPartitions()
	if err != nil {
		return nil, fmt.Errorf("kafka/admin: list topics: %w", err)
	}

	seen := make(map[string]bool)
	topics := make([]string, 0)
	for _, p := range partitions {
		if !seen[p.Topic] {
			seen[p.Topic] = true
			topics = append(topics, p.Topic)
		}
	}
	return topics, nil
}

// Close closes the admin connection.
func (a *Admin) Close() error {
	return a.conn.Close()
}

// filterTopicAlreadyExists returns nil if err is solely about
// topics already existing (safe to ignore), otherwise returns err.
func filterTopicAlreadyExists(err error) error {
	if err == nil {
		return nil
	}
	// kafka-go wraps these as a kafkago.Error with code 36 (TopicAlreadyExists)
	// We check the string as a safe fallback since the error type varies.
	if isTopicExistsError(err) {
		return nil
	}
	return err
}

func isTopicExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "TopicAlreadyExists") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "TOPIC_ALREADY_EXISTS")
}
