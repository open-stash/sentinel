package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/handler"
)

func Setup(authHandler *handler.AuthHandler, apiKeyHandler *handler.APIKeyHandler, oauthHandler *handler.OAuthHandler, authMiddleware gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// OAuth 2.1 discovery (must live at the domain root so MCP clients can find it).
	r.GET("/.well-known/oauth-authorization-server", oauthHandler.Metadata)
	r.GET("/.well-known/jwks.json", oauthHandler.JWKS)

	// OAuth 2.1 endpoints for the MCP server. register/token are public (PKCE is the
	// proof); /code is called server-side by the holonet consent page (user-authed).
	oauth := r.Group("/oauth")
	{
		oauth.POST("/register", oauthHandler.Register)
		oauth.POST("/token", oauthHandler.Token)
		oauth.POST("/code", authMiddleware, oauthHandler.IssueCode)
	}

	v1 := r.Group("/api/v1")

	auth := v1.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/introspect", authHandler.Introspect) // service-to-service token validation
		auth.GET("/verify-email", authHandler.VerifyEmail)
		auth.POST("/forgot-password", authHandler.ForgotPassword)
		auth.POST("/reset-password", authHandler.ResetPassword)

		protected := auth.Group("", authMiddleware)
		{
			protected.POST("/logout", authHandler.Logout)
			protected.GET("/me", authHandler.Me)
			protected.PATCH("/me", authHandler.UpdateProfile)
			protected.POST("/totp/setup", authHandler.SetupTOTP)
			protected.POST("/totp/enable", authHandler.EnableTOTP)

			// Session / device management
			protected.GET("/sessions", authHandler.ListSessions)
			protected.DELETE("/sessions/:id", authHandler.RevokeSession)
			protected.DELETE("/sessions", authHandler.RevokeOtherSessions)
		}
	}

	// API keys (for external MCP clients). /verify is service-to-service (no JWT);
	// the rest are user-scoped.
	keys := v1.Group("/keys")
	{
		keys.POST("/verify", apiKeyHandler.Verify)
		protected := keys.Group("", authMiddleware)
		{
			protected.POST("", apiKeyHandler.Create)
			protected.GET("", apiKeyHandler.List)
			protected.DELETE("/:id", apiKeyHandler.Revoke)
		}
	}

	// Connected apps (OAuth grants) — what the user has connected TO their memory.
	conns := v1.Group("/connections", authMiddleware)
	{
		conns.GET("", oauthHandler.ListConnections)
		conns.DELETE("/:client_id", oauthHandler.RevokeConnection)
	}

	return r
}
