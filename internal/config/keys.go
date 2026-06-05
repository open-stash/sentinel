package config

// Config key constants — use these instead of raw strings when calling vip.Get().
const (
	// Server
	KeyServerPort     = "server.port"
	KeyServerEnv      = "server.env"
	KeyServerGRPCPort = "server.grpc_port"

	// Database
	KeyDatabaseDSN             = "database.dsn"
	KeyDatabaseMaxOpenConns    = "database.max_open_conns"
	KeyDatabaseMaxIdleConns    = "database.max_idle_conns"
	KeyDatabaseConnMaxLifetime = "database.conn_max_lifetime"

	// Redis
	KeyRedisAddr     = "redis.addr"
	KeyRedisPassword = "redis.password"
	KeyRedisDB       = "redis.db"

	// JWT
	KeyJWTPrivateKeyPath  = "jwt.private_key_path"
	KeyJWTPublicKeyPath   = "jwt.public_key_path"
	KeyJWTAccessTokenTTL  = "jwt.access_token_ttl"
	KeyJWTRefreshTokenTTL = "jwt.refresh_token_ttl"

	// RabbitMQ (notification publisher → beacon)
	KeyRabbitMQBrokerURL    = "rabbitmq.broker_url"
	KeyRabbitMQExchangeName = "rabbitmq.exchange_name"
	KeyRabbitMQExchangeType = "rabbitmq.exchange_type"
	KeyRabbitMQRoutingKey   = "rabbitmq.routing_key"

	// App
	KeyAppFrontendBaseURL = "app.frontend_base_url"

	// Email
	KeyEmailProvider    = "email.provider"
	KeyEmailSendGridKey = "email.sendgrid_key"
	KeyEmailFromAddress = "email.from_address"
	KeyEmailFromName    = "email.from_name"

	// Auth
	KeyAuthRateLimitAttempts = "auth.rate_limit_attempts"
	KeyAuthRateLimitWindow   = "auth.rate_limit_window"
	KeyAuthPasswordMinLength = "auth.password_min_length"
	KeyAuthEmailVerifyTTL    = "auth.email_verify_ttl"
	KeyAuthPasswordResetTTL  = "auth.password_reset_ttl"
	KeyAuthRefreshCookieName = "auth.refresh_cookie_name"
	KeyAuthRefreshCookiePath = "auth.refresh_cookie_path"

	// TOTP
	KeyTOTPIssuer = "totp.issuer"
)
