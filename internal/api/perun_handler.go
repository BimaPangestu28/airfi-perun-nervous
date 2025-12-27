package api

import (
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/airfi/airfi-perun-nervous/internal/perun"
	"github.com/airfi/airfi-perun-nervous/internal/session"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PerunHandler handles API requests using real Perun channels.
type PerunHandler struct {
	perunClient    *perun.PerunClient
	sessionManager *session.Manager
	logger         *zap.Logger
}

// NewPerunHandler creates a new handler with real Perun client.
func NewPerunHandler(
	perunClient *perun.PerunClient,
	sessionManager *session.Manager,
	logger *zap.Logger,
) *PerunHandler {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &PerunHandler{
		perunClient:    perunClient,
		sessionManager: sessionManager,
		logger:         logger,
	}
}

// HealthCheck returns the service health status.
func (h *PerunHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"connected": h.perunClient.IsConnected(),
		"network":   "testnet",
	})
}

// WalletStatus returns the host wallet information.
func (h *PerunHandler) WalletStatus(c *gin.Context) {
	address := h.perunClient.GetAddress()

	// Query balance from CKB network
	balance, err := h.perunClient.GetBalance(c.Request.Context())
	balanceStr := "0"
	var balanceCKB float64
	if err == nil && balance != nil {
		balanceStr = balance.String()
		ckbFloat := new(big.Float).SetInt(balance)
		ckbFloat.Quo(ckbFloat, big.NewFloat(100000000))
		balanceCKB, _ = ckbFloat.Float64()
	}

	c.JSON(http.StatusOK, gin.H{
		"address":     address,
		"balance":     balanceStr,
		"balance_ckb": balanceCKB,
		"network":     "testnet",
		"connected":   h.perunClient.IsConnected(),
	})
}

// OpenChannelRequest represents a channel open request.
type PerunOpenChannelRequest struct {
	PeerAddress    string `json:"peer_address" binding:"required"`
	MyFundingCKB   int64  `json:"my_funding_ckb"`   // Host funding in CKB
	PeerFundingCKB int64  `json:"peer_funding_ckb"` // Guest funding in CKB
}

// Note: OpenChannel response now uses gin.H directly to include wallet explorer URL

// OpenChannel handles real Perun channel opening on CKB testnet.
func (h *PerunHandler) OpenChannel(c *gin.Context) {
	var req PerunOpenChannelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert CKB to shannons (1 CKB = 100,000,000 shannons)
	// Minimum funding is ~73 CKB per participant due to PFLS capacity
	myFunding := big.NewInt(req.MyFundingCKB * 100000000)
	peerFunding := big.NewInt(req.PeerFundingCKB * 100000000)

	// Default minimum funding if not specified
	if myFunding.Cmp(big.NewInt(0)) == 0 {
		myFunding = big.NewInt(10000000000) // 100 CKB
	}
	if peerFunding.Cmp(big.NewInt(0)) == 0 {
		peerFunding = big.NewInt(10000000000) // 100 CKB
	}

	h.logger.Info("opening Perun channel",
		zap.String("peer", req.PeerAddress),
		zap.String("my_funding", myFunding.String()),
		zap.String("peer_funding", peerFunding.String()),
	)

	// Open real Perun channel
	channel, err := h.perunClient.OpenChannel(c.Request.Context(), req.PeerAddress, myFunding, peerFunding)
	if err != nil {
		h.logger.Error("failed to open channel", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	channelIDHex := fmt.Sprintf("%x", channel.ID)

	// Create session if session manager available
	var sessionID string
	if h.sessionManager != nil {
		sess, err := h.sessionManager.CreateSession(channelIDHex, req.PeerAddress)
		if err == nil {
			sessionID = sess.ID
			// Activate session with initial funding
			_, _, err = h.sessionManager.ActivateSession(sess.ID, peerFunding)
			if err != nil {
				h.logger.Warn("failed to activate session", zap.Error(err))
			}
		}
	}

	// Generate wallet explorer URL to find actual funding TX
	walletExplorerURL := fmt.Sprintf("https://pudge.explorer.nervos.org/address/%s", h.perunClient.GetAddress())

	c.JSON(http.StatusOK, gin.H{
		"channel_id":      channelIDHex,
		"pcts_hash":       channel.FundingTx, // This is PCTS script hash, not TX hash
		"wallet_explorer": walletExplorerURL, // Check here for actual funding TX (~-904 CKB)
		"session_id":      sessionID,
		"my_balance":      channel.MyBalance.String(),
		"peer_balance":    channel.PeerBalance.String(),
		"status":          channel.State,
		"note":            "Funding TX visible in wallet explorer (look for -904 CKB transaction)",
	})
}

// PaymentRequest represents a payment request.
type PerunPaymentRequest struct {
	AmountCKB float64 `json:"amount_ckb" binding:"required"`
}

// SendPayment processes an off-chain payment in the channel.
func (h *PerunHandler) SendPayment(c *gin.Context) {
	channelID := c.Param("channelId")

	var req PerunPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert CKB to shannons
	amount := big.NewInt(int64(req.AmountCKB * 100000000))

	// Get channel and process payment
	channel, err := h.perunClient.GetChannelByString(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	// Send payment (off-chain state update)
	err = h.perunClient.SendPayment(channel.ID, amount)
	if err != nil {
		h.logger.Error("payment failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Refresh channel state
	channel, _ = h.perunClient.GetChannelByString(channelID)

	c.JSON(http.StatusOK, gin.H{
		"channel_id":   channelID,
		"amount":       amount.String(),
		"my_balance":   channel.MyBalance.String(),
		"peer_balance": channel.PeerBalance.String(),
		"status":       "payment_sent",
	})
}

// ReceivePayment receives an off-chain payment in the channel.
func (h *PerunHandler) ReceivePayment(c *gin.Context) {
	channelID := c.Param("channelId")

	var req PerunPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert CKB to shannons
	amount := big.NewInt(int64(req.AmountCKB * 100000000))

	// Get channel
	channel, err := h.perunClient.GetChannelByString(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	// Receive payment (off-chain state update)
	err = h.perunClient.ReceivePayment(channel.ID, amount)
	if err != nil {
		h.logger.Error("payment failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get or extend session
	if h.sessionManager != nil {
		sess, err := h.sessionManager.GetSessionByChannel(channelID)
		if err == nil {
			_, _, _ = h.sessionManager.ExtendSession(sess.ID, amount)
		}
	}

	// Refresh channel state
	channel, _ = h.perunClient.GetChannelByString(channelID)

	c.JSON(http.StatusOK, gin.H{
		"channel_id":   channelID,
		"amount":       amount.String(),
		"my_balance":   channel.MyBalance.String(),
		"peer_balance": channel.PeerBalance.String(),
		"status":       "payment_received",
	})
}

// SettleChannel handles channel settlement on-chain.
func (h *PerunHandler) SettleChannel(c *gin.Context) {
	channelID := c.Param("channelId")

	channel, err := h.perunClient.GetChannelByString(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	h.logger.Info("settling channel",
		zap.String("channel_id", channelID),
		zap.String("my_balance", channel.MyBalance.String()),
		zap.String("peer_balance", channel.PeerBalance.String()),
	)

	// Settle channel on-chain
	settleTxHash, err := h.perunClient.SettleChannel(c.Request.Context(), channel.ID)
	if err != nil {
		h.logger.Error("settlement failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// End associated session
	if h.sessionManager != nil {
		sess, err := h.sessionManager.GetSessionByChannel(channelID)
		if err == nil {
			_ = h.sessionManager.EndSession(c.Request.Context(), sess.ID)
		}
	}

	// Refresh channel state
	channel, _ = h.perunClient.GetChannelByString(channelID)

	c.JSON(http.StatusOK, gin.H{
		"channel_id":   channelID,
		"settle_tx":    settleTxHash,
		"explorer_url": fmt.Sprintf("https://pudge.explorer.nervos.org/transaction/%s", settleTxHash),
		"status":       channel.State,
		"my_balance":   channel.MyBalance.String(),
		"peer_balance": channel.PeerBalance.String(),
	})
}

// GetChannel returns channel information.
func (h *PerunHandler) GetChannel(c *gin.Context) {
	channelID := c.Param("channelId")

	channel, err := h.perunClient.GetChannelByString(channelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "channel not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"channel_id":   fmt.Sprintf("%x", channel.ID),
		"peer_address": channel.PeerAddress,
		"state":        channel.State,
		"my_balance":   channel.MyBalance.String(),
		"peer_balance": channel.PeerBalance.String(),
		"funding_tx":   channel.FundingTx,
		"created_at":   channel.CreatedAt.Format(time.RFC3339),
		"updated_at":   channel.UpdatedAt.Format(time.RFC3339),
	})
}

// ListChannels returns all active channels.
func (h *PerunHandler) ListChannels(c *gin.Context) {
	channels := h.perunClient.ListChannels()

	result := make([]gin.H, 0, len(channels))
	for _, ch := range channels {
		result = append(result, gin.H{
			"channel_id":   fmt.Sprintf("%x", ch.ID),
			"peer_address": ch.PeerAddress,
			"state":        ch.State,
			"my_balance":   ch.MyBalance.String(),
			"peer_balance": ch.PeerBalance.String(),
			"funding_tx":   ch.FundingTx,
			"created_at":   ch.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"channels": result,
		"count":    len(result),
	})
}
