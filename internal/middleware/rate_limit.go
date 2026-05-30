package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/repository"
)

// LoginRateLimit limits login attempts per client IP.
func LoginRateLimit(rateLimit repository.RateLimitRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		allowed, retryAfter, err := rateLimit.Allow(c.Request.Context(), ip)
		if err != nil {
			// Fail-open on Redis/rate limiter issues to avoid blocking valid users.
			c.Next()
			return
		}
		if allowed {
			c.Next()
			return
		}

		c.Header("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"success": false,
			"error":   fmt.Sprintf("too many login attempts, retry after %s", retryAfter),
		})
	}
}
