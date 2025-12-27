// Package api provides HTTP API for AirFi backend.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Router wraps the Gin engine with AirFi handlers.
type Router struct {
	engine  *gin.Engine
	handler *Handler
}

// NewRouter creates a new API router.
func NewRouter(handler *Handler) *Router {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	// Middleware
	engine.Use(gin.Recovery())
	engine.Use(corsMiddleware())

	r := &Router{
		engine:  engine,
		handler: handler,
	}

	r.setupRoutes()

	return r
}

// setupRoutes configures all API routes.
func (r *Router) setupRoutes() {
	// Health check
	r.engine.GET("/health", r.handler.HealthCheck)

	// API v1 routes
	v1 := r.engine.Group("/api/v1")
	{
		// Wallet status
		v1.GET("/wallet", r.handler.WalletStatus)
		v1.POST("/wallet/transfer", r.handler.Transfer)

		// Channel operations
		channels := v1.Group("/channels")
		{
			channels.POST("/open", r.handler.OpenChannel)
			channels.POST("/:channelId/pay", r.handler.ProcessPayment)
			channels.POST("/:channelId/settle", r.handler.SettleChannel)
			channels.GET("/:channelId", r.handler.GetChannel)
		}

		// Session operations
		sessions := v1.Group("/sessions")
		{
			sessions.GET("", r.handler.ListSessions)
			sessions.GET("/:sessionId", r.handler.GetSession)
			sessions.GET("/:sessionId/token", r.handler.GetSessionToken)
			sessions.POST("/:sessionId/extend", r.handler.ExtendSession)
			sessions.POST("/:sessionId/end", r.handler.EndSession)
		}

		// WiFi access (protected routes)
		wifi := v1.Group("/wifi")
		wifi.Use(r.handler.AuthMiddleware())
		{
			wifi.GET("/status", r.handler.GetWiFiStatus)
		}

		// Pricing info
		v1.GET("/pricing", r.handler.GetPricing)
	}

	// Guest portal (serves HTML)
	r.engine.Static("/static", "./web/guest/static")
	r.engine.LoadHTMLGlob("./web/guest/templates/*")

	r.engine.GET("/", r.handler.GuestIndex)
	r.engine.GET("/connect", r.handler.GuestConnect)
	r.engine.GET("/session/:sessionId", r.handler.GuestSession)
}

// Engine returns the underlying Gin engine.
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.engine.ServeHTTP(w, req)
}

// corsMiddleware adds CORS headers.
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// PerunRouter wraps the Gin engine with real Perun handlers.
type PerunRouter struct {
	engine  *gin.Engine
	handler *PerunHandler
}

// NewPerunRouter creates a new API router with real Perun channels.
func NewPerunRouter(handler *PerunHandler) *PerunRouter {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	// Middleware
	engine.Use(gin.Recovery())
	engine.Use(corsMiddleware())
	engine.Use(gin.Logger())

	r := &PerunRouter{
		engine:  engine,
		handler: handler,
	}

	r.setupRoutes()

	return r
}

// setupRoutes configures all API routes.
func (r *PerunRouter) setupRoutes() {
	// Health check
	r.engine.GET("/health", r.handler.HealthCheck)

	// API v1 routes - Real Perun Channels
	v1 := r.engine.Group("/api/v1")
	{
		// Wallet status
		v1.GET("/wallet", r.handler.WalletStatus)

		// Channel operations (Real Perun)
		channels := v1.Group("/channels")
		{
			channels.GET("", r.handler.ListChannels)
			channels.POST("/open", r.handler.OpenChannel)
			channels.POST("/:channelId/send", r.handler.SendPayment)
			channels.POST("/:channelId/receive", r.handler.ReceivePayment)
			channels.POST("/:channelId/settle", r.handler.SettleChannel)
			channels.GET("/:channelId", r.handler.GetChannel)
		}
	}
}

// Engine returns the underlying Gin engine.
func (r *PerunRouter) Engine() *gin.Engine {
	return r.engine
}

// ServeHTTP implements http.Handler.
func (r *PerunRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.engine.ServeHTTP(w, req)
}
