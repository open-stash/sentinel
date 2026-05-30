package config

import "time"

type ServerEnv string

const (
	LocalEnv ServerEnv = "local"
	ProdEnv  ServerEnv = "prod"
	DevEnv   ServerEnv = "dev"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Kafka    KafkaConfig
	Email    EmailConfig
	Auth     AuthConfig
	TOTP     TOTPConfig
}

type ServerConfig struct {
	Port     int       `mapstructure:"port"`
	Env      ServerEnv `mapstructure:"env"`
	GRPCPort int       `mapstructure:"grpc_port"`
}

type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MinIdleConns    int           `mapstructure:"min_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	HealthTimeout   time.Duration `mapstructure:"health_timeout"`
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type JWTConfig struct {
	PrivateKeyPath    string        `mapstructure:"private_key_path"`
	PublicKeyPath     string        `mapstructure:"public_key_path"`
	AccessTokenTTL    time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL   time.Duration `mapstructure:"refresh_token_ttl"`
}

type KafkaConfig struct {
	Brokers        []string `mapstructure:"brokers"`
	TopicRegistered string  `mapstructure:"topic_registered"`
	TopicLogin      string  `mapstructure:"topic_login"`
	TopicPwChanged  string  `mapstructure:"topic_pw_changed"`
}

type EmailConfig struct {
	Provider    string `mapstructure:"provider"`
	SendGridKey string `mapstructure:"sendgrid_key"`
	FromAddress string `mapstructure:"from_address"`
	FromName    string `mapstructure:"from_name"`
}

type AuthConfig struct {
	RateLimitAttempts int           `mapstructure:"rate_limit_attempts"`
	RateLimitWindow   time.Duration `mapstructure:"rate_limit_window"`
	PasswordMinLength int           `mapstructure:"password_min_length"`
	EmailVerifyTTL    time.Duration `mapstructure:"email_verify_ttl"`
	PasswordResetTTL  time.Duration `mapstructure:"password_reset_ttl"`
	RefreshCookieName string        `mapstructure:"refresh_cookie_name"`
	RefreshCookiePath string        `mapstructure:"refresh_cookie_path"`
}

type TOTPConfig struct {
	Issuer string `mapstructure:"issuer"`
}
