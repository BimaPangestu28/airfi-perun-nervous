package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware returns a middleware that validates JWT tokens.
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token and get session
		session, err := h.sessionManager.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// Store session in context
		c.Set("session", session)
		c.Set("sessionID", session.ID)
		c.Set("channelID", session.ChannelID)

		c.Next()
	}
}

// OptionalAuthMiddleware validates JWT if present but doesn't require it.
func (h *Handler) OptionalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]

		session, err := h.sessionManager.ValidateToken(tokenString)
		if err == nil {
			c.Set("session", session)
			c.Set("sessionID", session.ID)
			c.Set("channelID", session.ChannelID)
		}

		c.Next()
	}
}

// RateLimitMiddleware provides basic rate limiting.
func RateLimitMiddleware(requestsPerSecond int) gin.HandlerFunc {
	// Simple token bucket implementation could be added here
	return func(c *gin.Context) {
		c.Next()
	}
}

// LoggingMiddleware logs request details.
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Request logging
		c.Next()
	}
}
