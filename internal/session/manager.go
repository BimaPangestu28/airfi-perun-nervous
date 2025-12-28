package session

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/airfi/airfi-perun-nervous/internal/auth"
	"github.com/airfi/airfi-perun-nervous/internal/perun"
	"go.uber.org/zap"
)

// RateConfig defines the pricing configuration.
type RateConfig struct {
	CKBytesPerMinute *big.Int
	MinSessionTime   time.Duration
	MaxSessionTime   time.Duration
}

// DefaultRateConfig returns the default pricing configuration.
func DefaultRateConfig() *RateConfig {
	return &RateConfig{
		CKBytesPerMinute: big.NewInt(1),         // 1 CKByte per minute
		MinSessionTime:   5 * time.Minute,        // Minimum 5 minutes
		MaxSessionTime:   24 * time.Hour,         // Maximum 24 hours
	}
}

// Manager handles session lifecycle and payment coordination.
type Manager struct {
	store       *Store
	perunClient *perun.Client
	jwtService  *auth.JWTService
	rateConfig  *RateConfig
	logger      *zap.Logger

	// Background cleanup
	ctx    context.Context
	cancel context.CancelFunc
}

// NewManager creates a new session manager.
func NewManager(
	store *Store,
	perunClient *perun.Client,
	jwtService *auth.JWTService,
	rateConfig *RateConfig,
	logger *zap.Logger,
) *Manager {
	if rateConfig == nil {
		rateConfig = DefaultRateConfig()
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		store:       store,
		perunClient: perunClient,
		jwtService:  jwtService,
		rateConfig:  rateConfig,
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start background cleanup
	go m.cleanupLoop()

	return m
}

// CreateSession creates a new session from a channel opening.
func (m *Manager) CreateSession(channelID, guestAddr string) (*Session, error) {
	m.logger.Info("creating session",
		zap.String("channel_id", channelID),
		zap.String("guest_addr", guestAddr),
	)

	session, err := m.store.Create(channelID, guestAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	m.logger.Info("session created",
		zap.String("session_id", session.ID),
		zap.String("channel_id", channelID),
	)

	return session, nil
}

// ActivateSession activates a session after payment is confirmed.
func (m *Manager) ActivateSession(sessionID string, payment *big.Int) (*Session, string, error) {
	session, err := m.store.Get(sessionID)
	if err != nil {
		return nil, "", err
	}

	// Calculate duration based on payment
	duration := m.CalculateDuration(payment)
	if duration < m.rateConfig.MinSessionTime {
		return nil, "", fmt.Errorf("payment too small: minimum session time is %v", m.rateConfig.MinSessionTime)
	}

	if duration > m.rateConfig.MaxSessionTime {
		duration = m.rateConfig.MaxSessionTime
	}

	// Generate access token (MAC/IP not available in this flow)
	token, err := m.jwtService.GenerateToken(sessionID, session.ChannelID, "", "", duration)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Activate session with payment
	if err := m.store.Activate(sessionID, duration, token, payment); err != nil {
		return nil, "", fmt.Errorf("failed to activate session: %w", err)
	}

	// Get updated session
	session, _ = m.store.Get(sessionID)

	m.logger.Info("session activated",
		zap.String("session_id", sessionID),
		zap.Duration("duration", duration),
		zap.String("payment", payment.String()),
	)

	return session, token, nil
}

// ExtendSession extends a session with additional payment.
func (m *Manager) ExtendSession(sessionID string, payment *big.Int) (*Session, string, error) {
	session, err := m.store.Get(sessionID)
	if err != nil {
		return nil, "", err
	}

	if session.Status != SessionStatusActive {
		return nil, "", fmt.Errorf("session is not active")
	}

	// Calculate additional duration
	additionalDuration := m.CalculateDuration(payment)

	// Check max session time
	newTotalDuration := session.Duration + additionalDuration
	if newTotalDuration > m.rateConfig.MaxSessionTime {
		additionalDuration = m.rateConfig.MaxSessionTime - session.Duration
		if additionalDuration <= 0 {
			return nil, "", fmt.Errorf("session has reached maximum duration")
		}
	}

	// Extend session
	if err := m.store.Extend(sessionID, additionalDuration, payment); err != nil {
		return nil, "", fmt.Errorf("failed to extend session: %w", err)
	}

	// Generate new token with extended duration (MAC/IP not available in this flow)
	session, _ = m.store.Get(sessionID)
	newToken, err := m.jwtService.GenerateToken(sessionID, session.ChannelID, "", "", session.RemainingTime())
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate new token: %w", err)
	}

	session.Token = newToken

	m.logger.Info("session extended",
		zap.String("session_id", sessionID),
		zap.Duration("additional", additionalDuration),
		zap.Duration("remaining", session.RemainingTime()),
	)

	return session, newToken, nil
}

// EndSession ends a session and triggers settlement.
func (m *Manager) EndSession(ctx context.Context, sessionID string) error {
	session, err := m.store.Get(sessionID)
	if err != nil {
		return err
	}

	m.logger.Info("ending session",
		zap.String("session_id", sessionID),
		zap.String("channel_id", session.ChannelID),
	)

	// End the session
	if err := m.store.End(sessionID); err != nil {
		return fmt.Errorf("failed to end session: %w", err)
	}

	// Trigger channel settlement
	if m.perunClient != nil {
		if err := m.perunClient.CloseChannel(session.ChannelID); err != nil {
			m.logger.Warn("failed to close channel",
				zap.String("channel_id", session.ChannelID),
				zap.Error(err),
			)
		}
	}

	m.logger.Info("session ended",
		zap.String("session_id", sessionID),
	)

	return nil
}

// GetSession retrieves a session by ID.
func (m *Manager) GetSession(sessionID string) (*Session, error) {
	return m.store.Get(sessionID)
}

// GetSessionByChannel retrieves a session by channel ID.
func (m *Manager) GetSessionByChannel(channelID string) (*Session, error) {
	return m.store.GetByChannel(channelID)
}

// ListActiveSessions returns all active sessions.
func (m *Manager) ListActiveSessions() []*Session {
	return m.store.ListActive()
}

// CalculateDuration calculates session duration from payment amount.
func (m *Manager) CalculateDuration(payment *big.Int) time.Duration {
	if payment == nil || payment.Sign() <= 0 {
		return 0
	}

	// minutes = payment / rate
	rate := m.rateConfig.CKBytesPerMinute
	if rate.Sign() <= 0 {
		return 0
	}

	minutes := new(big.Int).Div(payment, rate)
	return time.Duration(minutes.Int64()) * time.Minute
}

// CalculatePrice calculates the payment required for a duration.
func (m *Manager) CalculatePrice(duration time.Duration) *big.Int {
	minutes := int64(duration.Minutes())
	return new(big.Int).Mul(m.rateConfig.CKBytesPerMinute, big.NewInt(minutes))
}

// ValidateToken validates an access token.
func (m *Manager) ValidateToken(tokenString string) (*Session, error) {
	claims, err := m.jwtService.ValidateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	session, err := m.store.Get(claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if !session.IsActive() {
		return nil, fmt.Errorf("session is not active")
	}

	return session, nil
}

// Stop stops the manager and cleanup routines.
func (m *Manager) Stop() {
	m.cancel()
}

// cleanupLoop periodically checks for expired sessions.
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkExpiredSessions()
		}
	}
}

// checkExpiredSessions marks expired sessions.
func (m *Manager) checkExpiredSessions() {
	sessions := m.store.ListAll()

	for _, session := range sessions {
		if session.Status == SessionStatusActive && !session.IsActive() {
			m.logger.Info("marking session as expired",
				zap.String("session_id", session.ID),
			)
			_ = m.store.MarkExpired(session.ID)
		}
	}
}
