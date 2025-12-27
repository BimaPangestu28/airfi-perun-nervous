package api

import (
	"math/big"
	"net/http"
	"time"

	"github.com/airfi/airfi-perun-nervous/internal/perun"
	"github.com/airfi/airfi-perun-nervous/internal/session"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler contains all HTTP handlers for the API.
type Handler struct {
	perunClient    *perun.Client
	sessionManager *session.Manager
	logger         *zap.Logger
}

// NewHandler creates a new API handler.
func NewHandler(
	perunClient *perun.Client,
	sessionManager *session.Manager,
	logger *zap.Logger,
) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Handler{
		perunClient:    perunClient,
		sessionManager: sessionManager,
		logger:         logger,
	}
}

// HealthCheck returns the service health status.
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"connected": h.perunClient.IsConnected(),
	})
}

// WalletStatus returns the host wallet information.
func (h *Handler) WalletStatus(c *gin.Context) {
	address := h.perunClient.GetAddress()

	// Query balance from CKB network
	balance, err := h.perunClient.GetBalance(c.Request.Context())
	balanceStr := "0"
	var balanceCKB float64
	if err == nil && balance != nil {
		balanceStr = balance.String()
		// Convert to CKB (8 decimals)
		ckbFloat := new(big.Float).SetInt(balance)
		ckbFloat.Quo(ckbFloat, big.NewFloat(100000000))
		balanceCKB, _ = ckbFloat.Float64()
	}

	c.JSON(http.StatusOK, gin.H{
		"address":      address,
		"balance":      balanceStr,
		"balance_ckb":  balanceCKB,
		"network":      h.perunClient.GetConfig().Network,
		"connected":    h.perunClient.IsConnected(),
	})
}

// OpenChannelRequest represents a channel open request.
type OpenChannelRequest struct {
	GuestAddress string `json:"guest_address" binding:"required"`
	FundingAmount string `json:"funding_amount" binding:"required"`
}

// OpenChannelResponse represents a channel open response.
type OpenChannelResponse struct {
	ChannelID string `json:"channel_id"`
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

// OpenChannel handles channel opening.
func (h *Handler) OpenChannel(c *gin.Context) {
	var req OpenChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fundingAmount, ok := new(big.Int).SetString(req.FundingAmount, 10)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid funding amount"})
		return
	}

	// Open Perun channel
	channel, err := h.perunClient.OpenChannel(c.Request.Context(), &perun.OpenChannelRequest{
		PeerAddress: req.GuestAddress,
		MyFunding:   big.NewInt(0), // Provider doesn't fund
		PeerFunding: fundingAmount,
	})
	if err != nil {
		h.logger.Error("failed to open channel", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open channel"})
		return
	}

	// Create session
	sess, err := h.sessionManager.CreateSession(channel.ID, req.GuestAddress)
	if err != nil {
		h.logger.Error("failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	// Activate session immediately with funding amount
	sess, _, err = h.sessionManager.ActivateSession(sess.ID, fundingAmount)
	if err != nil {
		h.logger.Error("failed to activate session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to activate session"})
		return
	}

	c.JSON(http.StatusOK, OpenChannelResponse{
		ChannelID: channel.ID,
		SessionID: sess.ID,
		Status:    string(sess.Status),
	})
}

// PaymentRequest represents a payment request.
type PaymentRequest struct {
	Amount string `json:"amount" binding:"required"`
}

// PaymentResponse represents a payment response.
type PaymentResponse struct {
	SessionID   string `json:"session_id"`
	Token       string `json:"token"`
	Duration    string `json:"duration"`
	ExpiresAt   string `json:"expires_at"`
	MyBalance   string `json:"my_balance"`
	PeerBalance string `json:"peer_balance"`
}

// ProcessPayment handles a micropayment in the channel.
func (h *Handler) ProcessPayment(c *gin.Context) {
	channelID := c.Param("channelId")

	var req PaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid amount"})
		return
	}

	// Get channel and process payment
	channel, err := h.perunClient.GetChannel(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	// Receive payment (provider receives from guest)
	_, err = channel.ReceivePayment(c.Request.Context(), amount)
	if err != nil {
		h.logger.Error("payment failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get or activate session
	sess, err := h.sessionManager.GetSessionByChannel(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	var token string
	if sess.Status == session.SessionStatusPending {
		// First payment - activate session
		sess, token, err = h.sessionManager.ActivateSession(sess.ID, amount)
	} else {
		// Additional payment - extend session
		sess, token, err = h.sessionManager.ExtendSession(sess.ID, amount)
	}

	if err != nil {
		h.logger.Error("session operation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	myBalance, peerBalance := channel.GetBalances()

	c.JSON(http.StatusOK, PaymentResponse{
		SessionID:   sess.ID,
		Token:       token,
		Duration:    sess.Duration.String(),
		ExpiresAt:   sess.StartTime.Add(sess.Duration).Format(time.RFC3339),
		MyBalance:   myBalance.String(),
		PeerBalance: peerBalance.String(),
	})
}

// SettleChannel handles channel settlement.
func (h *Handler) SettleChannel(c *gin.Context) {
	channelID := c.Param("channelId")

	channel, err := h.perunClient.GetChannel(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	if err := channel.Settle(c.Request.Context()); err != nil {
		h.logger.Error("settlement failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "settlement failed"})
		return
	}

	// End associated session
	sess, err := h.sessionManager.GetSessionByChannel(channelID)
	if err == nil {
		_ = h.sessionManager.EndSession(c.Request.Context(), sess.ID)
	}

	myBalance, peerBalance := channel.GetBalances()

	c.JSON(http.StatusOK, gin.H{
		"channel_id":   channelID,
		"status":       string(channel.State),
		"my_balance":   myBalance.String(),
		"peer_balance": peerBalance.String(),
	})
}

// TransferRequest represents a CKB transfer request.
type TransferRequest struct {
	ToAddress string `json:"to_address" binding:"required"`
	Amount    string `json:"amount" binding:"required"`
}

// Transfer handles CKB transfer (for testing on-chain transactions).
func (h *Handler) Transfer(c *gin.Context) {
	var req TransferRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid amount"})
		return
	}

	h.logger.Info("initiating transfer",
		zap.String("to", req.ToAddress),
		zap.String("amount", amount.String()),
	)

	txHash, err := h.perunClient.Transfer(c.Request.Context(), req.ToAddress, amount)
	if err != nil {
		h.logger.Error("transfer failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tx_hash":     txHash,
		"status":      "submitted",
		"explorer":    "https://pudge.explorer.nervos.org/transaction/" + txHash,
		"to_address":  req.ToAddress,
		"amount":      amount.String(),
	})
}

// GetChannel returns channel information.
func (h *Handler) GetChannel(c *gin.Context) {
	channelID := c.Param("channelId")

	channel, err := h.perunClient.GetChannel(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	myBalance, peerBalance := channel.GetBalances()

	c.JSON(http.StatusOK, gin.H{
		"channel_id":    channelID,
		"peer_address":  channel.PeerAddress,
		"state":         string(channel.State),
		"version":       channel.Version,
		"my_balance":    myBalance.String(),
		"peer_balance":  peerBalance.String(),
		"total_funding": channel.TotalFunding.String(),
		"created_at":    channel.CreatedAt.Format(time.RFC3339),
		"updated_at":    channel.UpdatedAt.Format(time.RFC3339),
	})
}

// GetSession returns session information.
func (h *Handler) GetSession(c *gin.Context) {
	sessionID := c.Param("sessionId")

	sess, err := h.sessionManager.GetSession(sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id":     sess.ID,
		"channel_id":     sess.ChannelID,
		"guest_address":  sess.GuestAddr,
		"status":         string(sess.Status),
		"remaining_time": sess.RemainingTimeFormatted(),
		"total_paid":     sess.TotalPaid.String(),
		"created_at":     sess.CreatedAt.Format(time.RFC3339),
	})
}

// ListSessions returns all sessions.
func (h *Handler) ListSessions(c *gin.Context) {
	sessions := h.sessionManager.ListActiveSessions()

	result := make([]gin.H, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, gin.H{
			"session_id":     sess.ID,
			"channel_id":     sess.ChannelID,
			"guest_address":  sess.GuestAddr,
			"status":         string(sess.Status),
			"remaining_time": sess.RemainingTimeFormatted(),
			"total_paid":     sess.TotalPaid.String(),
			"created_at":     sess.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": result,
		"count":    len(result),
	})
}

// GetSessionToken returns the JWT for a session.
func (h *Handler) GetSessionToken(c *gin.Context) {
	sessionID := c.Param("sessionId")

	sess, err := h.sessionManager.GetSession(sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	if sess.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session not activated"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":          sess.Token,
		"remaining_time": sess.RemainingTimeFormatted(),
	})
}

// ExtendSession extends a session with additional payment.
func (h *Handler) ExtendSession(c *gin.Context) {
	sessionID := c.Param("sessionId")

	var req PaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid amount"})
		return
	}

	sess, token, err := h.sessionManager.ExtendSession(sessionID, amount)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id":     sess.ID,
		"token":          token,
		"remaining_time": sess.RemainingTimeFormatted(),
		"total_paid":     sess.TotalPaid.String(),
	})
}

// EndSession ends a session.
func (h *Handler) EndSession(c *gin.Context) {
	sessionID := c.Param("sessionId")

	if err := h.sessionManager.EndSession(c.Request.Context(), sessionID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"session_id": sessionID,
		"status":     "ended",
	})
}

// GetWiFiStatus returns WiFi access status for authenticated users.
func (h *Handler) GetWiFiStatus(c *gin.Context) {
	sess, exists := c.Get("session")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	s := sess.(*session.Session)

	c.JSON(http.StatusOK, gin.H{
		"connected":      true,
		"session_id":     s.ID,
		"remaining_time": s.RemainingTimeFormatted(),
	})
}

// GetPricing returns the pricing information.
func (h *Handler) GetPricing(c *gin.Context) {
	rateConfig := session.DefaultRateConfig()

	c.JSON(http.StatusOK, gin.H{
		"ckbytes_per_minute": rateConfig.CKBytesPerMinute.String(),
		"min_session_time":   rateConfig.MinSessionTime.String(),
		"max_session_time":   rateConfig.MaxSessionTime.String(),
		"prices": gin.H{
			"5_minutes":  h.sessionManager.CalculatePrice(5 * time.Minute).String(),
			"30_minutes": h.sessionManager.CalculatePrice(30 * time.Minute).String(),
			"1_hour":     h.sessionManager.CalculatePrice(1 * time.Hour).String(),
			"24_hours":   h.sessionManager.CalculatePrice(24 * time.Hour).String(),
		},
	})
}

// Guest portal handlers

// GuestIndex serves the guest landing page.
func (h *Handler) GuestIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "AirFi - WiFi Access",
	})
}

// GuestConnect serves the wallet connection page.
func (h *Handler) GuestConnect(c *gin.Context) {
	c.HTML(http.StatusOK, "connect.html", gin.H{
		"title": "Connect Wallet - AirFi",
	})
}

// GuestSession serves the active session page.
func (h *Handler) GuestSession(c *gin.Context) {
	sessionID := c.Param("sessionId")

	sess, err := h.sessionManager.GetSession(sessionID)
	if err != nil {
		c.HTML(http.StatusNotFound, "index.html", gin.H{
			"title": "Session Not Found",
			"error": "Session not found",
		})
		return
	}

	c.HTML(http.StatusOK, "session.html", gin.H{
		"title":         "Your Session - AirFi",
		"session":       sess,
		"remainingTime": sess.RemainingTimeFormatted(),
	})
}
