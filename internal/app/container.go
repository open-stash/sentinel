package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-stash/sentinel/internal/config"
	"github.com/open-stash/sentinel/internal/handler"
	"github.com/open-stash/sentinel/internal/middleware"
	"github.com/open-stash/sentinel/internal/repository"
	pgrepo "github.com/open-stash/sentinel/internal/repository/postgres"
	rrepo "github.com/open-stash/sentinel/internal/repository/rdb"
	"github.com/open-stash/sentinel/internal/router"
	"github.com/open-stash/sentinel/internal/service"
	dbpkg "github.com/open-stash/sentinel/pkg/db"
	jwtpkg "github.com/open-stash/sentinel/pkg/jwt"
	"github.com/open-stash/sentinel/pkg/mq"
	redispkg "github.com/open-stash/sentinel/pkg/redis"
)

type Container struct {
	Config config.Config

	DBPool *pgxpool.Pool
	DB     *dbpkg.Queries

	RedisClient redispkg.Client
	JWTSigner   *jwtpkg.Signer
	MQPublisher *mq.Publisher

	UserRepo      repository.UserRepository
	RefreshRepo   repository.RefreshTokenRepository
	BlacklistRepo repository.BlacklistRepository
	RateLimitRepo repository.RateLimitRepository
	EmailVerRepo  repository.EmailVerificationRepository
	PassResetRepo repository.PasswordResetRepository

	AuthService *service.AuthService
	AuthHandler *handler.AuthHandler

	AuthMiddleware      gin.HandlerFunc
	LoginRateMiddleware gin.HandlerFunc
	Router              *gin.Engine
}

func NewContainer(ctx context.Context) (*Container, error) {
	// Reject unknown JSON fields globally so payload typos don't pass silently.
	gin.EnableJsonDecoderDisallowUnknownFields()

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	dbPool, err := dbpkg.ConnectToDB(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("connect db: %w", err)
	}
	queries := dbpkg.New(dbPool)

	redisClient, err := redispkg.NewClient(ctx, &redispkg.Config{
		Addr:      cfg.Redis.Addr,
		Password:  cfg.Redis.Password,
		DB:        cfg.Redis.DB,
		KeyPrefix: fmt.Sprintf("auth:%s", cfg.Server.Env),
	})
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("connect redis: %w", err)
	}

	jwtSigner, err := jwtpkg.NewSigner(cfg.JWT)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("create jwt signer: %w", err)
	}

	mqPublisher, err := mq.NewPublisher(cfg.RabbitMQ)
	if err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("create rabbitmq publisher: %w", err)
	}

	userRepo := pgrepo.NewUserRepository(queries)
	refreshRepo := pgrepo.NewRefreshTokenRepository(queries)
	emailVerRepo := pgrepo.NewEmailVerificationRepository(queries)
	passResetRepo := pgrepo.NewPasswordResetRepository(queries)
	blacklistRepo := rrepo.NewBlacklistRepository(redisClient)
	rateLimitRepo := rrepo.NewRateLimitRepository(
		redisClient,
		uint64(cfg.Auth.RateLimitAttempts),
		cfg.Auth.RateLimitWindow,
	)

	authSvc := service.NewAuthService(
		userRepo,
		refreshRepo,
		blacklistRepo,
		rateLimitRepo,
		emailVerRepo,
		passResetRepo,
		jwtSigner,
		mqPublisher,
		cfg,
	)

	authHandler := handler.NewAuthHandler(authSvc)
	authMiddleware := middleware.AuthRequired(jwtSigner, blacklistRepo)
	loginRateMiddleware := middleware.LoginRateLimit(rateLimitRepo)
	httpRouter := router.Setup(authHandler, authMiddleware, loginRateMiddleware)

	return &Container{
		Config: cfg,

		DBPool: dbPool,
		DB:     queries,

		RedisClient: redisClient,
		JWTSigner:   jwtSigner,
		MQPublisher: mqPublisher,

		UserRepo:      userRepo,
		RefreshRepo:   refreshRepo,
		BlacklistRepo: blacklistRepo,
		RateLimitRepo: rateLimitRepo,
		EmailVerRepo:  emailVerRepo,
		PassResetRepo: passResetRepo,

		AuthService: authSvc,
		AuthHandler: authHandler,

		AuthMiddleware:      authMiddleware,
		LoginRateMiddleware: loginRateMiddleware,
		Router:              httpRouter,
	}, nil
}

// Shutdown releases resources owned by the container.
func (c *Container) Shutdown(_ context.Context) error {
	if c == nil {
		return nil
	}

	var errAll error

	if c.MQPublisher != nil {
		if err := c.MQPublisher.Close(); err != nil {
			errAll = errors.Join(errAll, err)
		}
	}

	if c.DBPool != nil {
		c.DBPool.Close()
	}

	return errAll
}
