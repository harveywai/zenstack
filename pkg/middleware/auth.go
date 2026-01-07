package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/harveywai/zenstack/pkg/auth"
)

const (
	contextUserIDKey = "userID"
	contextUserRole  = "userRole"
)

// AuthMiddleware validates the JWT token in the Authorization header and
// attaches user information to the Gin context for downstream handlers.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header is required",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header must be in the format 'Bearer <token>'",
			})
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authorization token is empty",
			})
			return
		}

		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		// Store user ID and role in context for downstream handlers.
		c.Set(contextUserIDKey, claims.UserID)
		c.Set(contextUserRole, claims.Role)

		c.Next()
	}
}

// RoleMiddleware ensures that the authenticated user has the required role.
// It should be used in combination with AuthMiddleware.
func RoleMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get(contextUserRole)
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "missing user role in context",
			})
			return
		}

		role, ok := roleVal.(string)
		if !ok || !strings.EqualFold(role, requiredRole) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "insufficient permissions",
			})
			return
		}

		c.Next()
	}
}
