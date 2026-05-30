package redis

import "fmt"

// Config holds everything needed to connect to Redis.
type Config struct {
	Addr     string // e.g. "localhost:6379"
	Password string // empty = no auth
	DB       int    // 0 = default DB
	KeyPrefix string
}

func (c *Config) Validate() error {
	if c.Addr == "" {
		return fmt.Errorf("redis: Addr is required")
	}
	if c.KeyPrefix == "" {
		return fmt.Errorf("redis: KeyPrefix is required")
	}
	return nil
}
