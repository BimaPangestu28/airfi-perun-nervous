// Package session provides WiFi session management for AirFi.
package session

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionStatus represents the current status of a session.
type SessionStatus string

const (
	// SessionStatusPending indicates session is awaiting payment.
	SessionStatusPending SessionStatus = "pending"
	// SessionStatusActive indicates session is active and connected.
	SessionStatusActive SessionStatus = "active"
	// SessionStatusExpired indicates session time has run out.
	SessionStatusExpired SessionStatus = "expired"
	// SessionStatusEnded indicates session was manually ended.
	SessionStatusEnded SessionStatus = "ended"
)

// Session represents a WiFi access session.
type Session struct {
	ID          string
	ChannelID   string
	GuestAddr   string
	Status      SessionStatus
	StartTime   time.Time
	EndTime     *time.Time
	Duration    time.Duration
	TotalPaid   *big.Int
	Token       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsActive returns true if the session is currently active.
func (s *Session) IsActive() bool {
	if s.Status != SessionStatusActive {
		return false
	}
	return time.Now().Before(s.StartTime.Add(s.Duration))
}

// RemainingTime returns the remaining session time.
func (s *Session) RemainingTime() time.Duration {
	if !s.IsActive() {
		return 0
	}
	remaining := s.StartTime.Add(s.Duration).Sub(time.Now())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RemainingTimeFormatted returns a human-readable remaining time string.
func (s *Session) RemainingTimeFormatted() string {
	remaining := s.RemainingTime()
	if remaining <= 0 {
		return "0s"
	}

	hours := int(remaining.Hours())
	minutes := int(remaining.Minutes()) % 60
	seconds := int(remaining.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Store provides in-memory session storage.
type Store struct {
	sessions map[string]*Session
	byChannel map[string]string // channelID -> sessionID
	mu       sync.RWMutex
}

// NewStore creates a new session store.
func NewStore() *Store {
	return &Store{
		sessions:  make(map[string]*Session),
		byChannel: make(map[string]string),
	}
}

// Create creates a new session.
func (s *Store) Create(channelID, guestAddr string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if channel already has a session
	if existingID, exists := s.byChannel[channelID]; exists {
		if session, ok := s.sessions[existingID]; ok && session.IsActive() {
			return nil, fmt.Errorf("channel %s already has an active session", channelID)
		}
	}

	session := &Session{
		ID:        uuid.New().String(),
		ChannelID: channelID,
		GuestAddr: guestAddr,
		Status:    SessionStatusPending,
		TotalPaid: big.NewInt(0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	s.sessions[session.ID] = session
	s.byChannel[channelID] = session.ID

	return session, nil
}

// Get retrieves a session by ID.
func (s *Store) Get(sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session, nil
}

// GetByChannel retrieves a session by channel ID.
func (s *Store) GetByChannel(channelID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionID, exists := s.byChannel[channelID]
	if !exists {
		return nil, fmt.Errorf("no session for channel: %s", channelID)
	}

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session, nil
}

// Activate activates a session with the given duration and payment.
func (s *Store) Activate(sessionID string, duration time.Duration, token string, payment *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Status = SessionStatusActive
	session.StartTime = time.Now()
	session.Duration = duration
	session.Token = token
	session.TotalPaid = new(big.Int).Set(payment)
	session.UpdatedAt = time.Now()

	return nil
}

// Extend extends a session by the given duration.
func (s *Store) Extend(sessionID string, additionalDuration time.Duration, payment *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if session.Status != SessionStatusActive {
		return fmt.Errorf("session is not active")
	}

	session.Duration += additionalDuration
	session.TotalPaid.Add(session.TotalPaid, payment)
	session.UpdatedAt = time.Now()

	return nil
}

// End ends a session.
func (s *Store) End(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	now := time.Now()
	session.Status = SessionStatusEnded
	session.EndTime = &now
	session.UpdatedAt = now

	return nil
}

// MarkExpired marks a session as expired.
func (s *Store) MarkExpired(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	now := time.Now()
	session.Status = SessionStatusExpired
	session.EndTime = &now
	session.UpdatedAt = now

	return nil
}

// ListActive returns all active sessions.
func (s *Store) ListActive() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*Session
	for _, session := range s.sessions {
		if session.IsActive() {
			active = append(active, session)
		}
	}

	return active
}

// ListAll returns all sessions.
func (s *Store) ListAll() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// Delete removes a session from the store.
func (s *Store) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	delete(s.byChannel, session.ChannelID)
	delete(s.sessions, sessionID)

	return nil
}

// Count returns the number of sessions.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// ActiveCount returns the number of active sessions.
func (s *Store) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, session := range s.sessions {
		if session.IsActive() {
			count++
		}
	}

	return count
}
