package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/repository"
	jwtpkg "github.com/open-stash/sentinel/pkg/jwt"
)

const claimsKey = "claims"

// AuthRequired validates the Bearer token, checks the JTI blacklist, and
// injects the parsed claims into the gin context under the "claims" key.
func AuthRequired(signer *jwtpkg.Signer, blacklist repository.BlacklistRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "missing or invalid authorization header",
			})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := signer.Verify(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "invalid or expired token",
			})
			return
		}

		blacklisted, err := blacklist.Contains(c.Request.Context(), claims.ID)
		if err != nil || blacklisted {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "token has been revoked",
			})
			return
		}

		c.Set(claimsKey, claims)
		c.Next()
	}
}
