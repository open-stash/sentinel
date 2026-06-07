package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/handler"
)

func Setup(authHandler *handler.AuthHandler, authMiddleware gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

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
			protected.POST("/totp/setup", authHandler.SetupTOTP)
			protected.POST("/totp/enable", authHandler.EnableTOTP)

			// Session / device management
			protected.GET("/sessions", authHandler.ListSessions)
			protected.DELETE("/sessions/:id", authHandler.RevokeSession)
			protected.DELETE("/sessions", authHandler.RevokeOtherSessions)
		}
	}

	return r
}
