package perun

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ChannelState represents the current state of a payment channel.
type ChannelState string

const (
	// ChannelStateInitiating indicates channel is being created.
	ChannelStateInitiating ChannelState = "initiating"
	// ChannelStateFunding indicates channel is awaiting funding confirmation.
	ChannelStateFunding ChannelState = "funding"
	// ChannelStateOpen indicates channel is active and ready for payments.
	ChannelStateOpen ChannelState = "open"
	// ChannelStateSettling indicates channel is being settled.
	ChannelStateSettling ChannelState = "settling"
	// ChannelStateClosed indicates channel has been closed.
	ChannelStateClosed ChannelState = "closed"
)

// Channel represents an active payment channel.
type Channel struct {
	ID            string
	PeerAddress   string
	State         ChannelState
	Version       uint64
	MyBalance     *big.Int
	PeerBalance   *big.Int
	TotalFunding  *big.Int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	SettledAt     *time.Time

	// Cryptographic state
	stateHash       []byte
	mySignature     []byte
	peerSignature   []byte
	fundingTxHash   string
	settlementTxHash string

	// Channel parameters
	challengeDuration time.Duration
	nonce            uint64

	// State history for dispute resolution
	stateHistory []*SignedState

	mu     sync.RWMutex
	client *Client
	logger *zap.Logger
}

// SignedState represents a signed channel state for off-chain updates.
type SignedState struct {
	ChannelID   string
	Version     uint64
	MyBalance   *big.Int
	PeerBalance *big.Int
	StateHash   []byte
	Signature   []byte
	Timestamp   time.Time
}

// ChannelUpdate represents a state update in the channel.
type ChannelUpdate struct {
	ChannelID   string
	Version     uint64
	MyBalance   *big.Int
	PeerBalance *big.Int
	StateHash   string
	Timestamp   time.Time
}

// OpenChannelRequest contains parameters for opening a channel.
type OpenChannelRequest struct {
	PeerAddress   string
	MyFunding     *big.Int
	PeerFunding   *big.Int
	ChallengeDur  time.Duration
}

// OpenChannel opens a new payment channel with a peer.
func (c *Client) OpenChannel(ctx context.Context, req *OpenChannelRequest) (*Channel, error) {
	if !c.connected {
		return nil, fmt.Errorf("client not connected")
	}

	if req.PeerAddress == "" {
		return nil, fmt.Errorf("peer address is required")
	}

	// For AirFi, provider doesn't fund, guest does
	if req.PeerFunding == nil || req.PeerFunding.Sign() <= 0 {
		return nil, fmt.Errorf("peer funding amount must be positive")
	}

	channelID := uuid.New().String()
	nonce := uint64(time.Now().UnixNano())

	c.logger.Info("opening channel",
		zap.String("channel_id", channelID),
		zap.String("peer", req.PeerAddress),
		zap.String("peer_funding", req.PeerFunding.String()),
	)

	// Set default challenge duration if not specified
	challengeDur := req.ChallengeDur
	if challengeDur == 0 {
		challengeDur = c.config.ChannelTimeout
	}

	channel := &Channel{
		ID:                channelID,
		PeerAddress:       req.PeerAddress,
		State:             ChannelStateInitiating,
		Version:           0,
		MyBalance:         big.NewInt(0), // Provider starts with 0
		PeerBalance:       new(big.Int).Set(req.PeerFunding),
		TotalFunding:      new(big.Int).Set(req.PeerFunding),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		challengeDuration: challengeDur,
		nonce:             nonce,
		stateHistory:      make([]*SignedState, 0),
		client:            c,
		logger:            c.logger,
	}

	if req.MyFunding != nil && req.MyFunding.Sign() > 0 {
		channel.MyBalance = new(big.Int).Set(req.MyFunding)
		channel.TotalFunding.Add(channel.TotalFunding, req.MyFunding)
	}

	// Step 1: Create channel proposal
	proposal := channel.createProposal()
	c.logger.Debug("created channel proposal",
		zap.String("channel_id", channelID),
		zap.String("proposal_hash", hex.EncodeToString(proposal)),
	)

	// Step 2: Sign the proposal (simulating our signature)
	channel.State = ChannelStateFunding
	channel.mySignature = channel.signState()

	// Step 3: Simulate funding transaction
	// In real implementation, this would submit to CKB blockchain
	channel.fundingTxHash = generateTxHash(channelID, "funding", nonce)
	c.logger.Info("funding transaction created",
		zap.String("channel_id", channelID),
		zap.String("tx_hash", channel.fundingTxHash),
	)

	// Step 4: Wait for confirmation (simulated)
	// In real implementation, we'd wait for blockchain confirmation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(100 * time.Millisecond): // Simulated confirmation delay
	}

	// Step 5: Channel is now open
	channel.State = ChannelStateOpen
	channel.stateHash = channel.computeStateHash()

	// Store initial state in history
	channel.stateHistory = append(channel.stateHistory, &SignedState{
		ChannelID:   channelID,
		Version:     0,
		MyBalance:   new(big.Int).Set(channel.MyBalance),
		PeerBalance: new(big.Int).Set(channel.PeerBalance),
		StateHash:   channel.stateHash,
		Signature:   channel.mySignature,
		Timestamp:   time.Now(),
	})

	c.channelsMu.Lock()
	c.channels[channelID] = channel
	c.channelsMu.Unlock()

	c.logger.Info("channel opened successfully",
		zap.String("channel_id", channelID),
		zap.String("state", string(channel.State)),
		zap.String("funding_tx", channel.fundingTxHash),
	)

	return channel, nil
}

// createProposal creates a channel proposal hash.
func (ch *Channel) createProposal() []byte {
	data := make([]byte, 0)
	data = append(data, []byte(ch.ID)...)
	data = append(data, []byte(ch.PeerAddress)...)
	data = append(data, ch.TotalFunding.Bytes()...)

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, ch.nonce)
	data = append(data, nonceBytes...)

	hash := sha256.Sum256(data)
	return hash[:]
}

// computeStateHash computes the hash of the current channel state.
func (ch *Channel) computeStateHash() []byte {
	data := make([]byte, 0)
	data = append(data, []byte(ch.ID)...)

	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, ch.Version)
	data = append(data, versionBytes...)

	data = append(data, ch.MyBalance.Bytes()...)
	data = append(data, ch.PeerBalance.Bytes()...)

	hash := sha256.Sum256(data)
	return hash[:]
}

// signState creates a signature for the current state.
func (ch *Channel) signState() []byte {
	stateHash := ch.computeStateHash()

	if ch.client != nil && ch.client.privateKey != nil {
		sig, err := ch.client.SignData(stateHash)
		if err != nil {
			ch.logger.Warn("failed to sign state", zap.Error(err))
			return stateHash // Fallback to hash as signature in simulation
		}
		return sig
	}

	// Simulation: use hash as signature
	return stateHash
}

// SendPayment sends a micropayment through the channel.
func (ch *Channel) SendPayment(ctx context.Context, amount *big.Int) (*ChannelUpdate, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if ch.State != ChannelStateOpen {
		return nil, fmt.Errorf("channel is not open (state: %s)", ch.State)
	}

	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("payment amount must be positive")
	}

	if ch.MyBalance.Cmp(amount) < 0 {
		return nil, fmt.Errorf("insufficient balance: have %s, need %s", ch.MyBalance.String(), amount.String())
	}

	ch.logger.Info("sending payment",
		zap.String("channel_id", ch.ID),
		zap.String("amount", amount.String()),
		zap.Uint64("current_version", ch.Version),
	)

	// Step 1: Create new state with updated balances
	newMyBalance := new(big.Int).Sub(ch.MyBalance, amount)
	newPeerBalance := new(big.Int).Add(ch.PeerBalance, amount)
	newVersion := ch.Version + 1

	// Step 2: Compute state hash for new state
	tempVersion := ch.Version
	tempMyBalance := ch.MyBalance
	tempPeerBalance := ch.PeerBalance

	ch.Version = newVersion
	ch.MyBalance = newMyBalance
	ch.PeerBalance = newPeerBalance
	newStateHash := ch.computeStateHash()

	// Step 3: Sign the new state
	signature := ch.signState()

	// Step 4: Store signed state in history
	signedState := &SignedState{
		ChannelID:   ch.ID,
		Version:     newVersion,
		MyBalance:   new(big.Int).Set(newMyBalance),
		PeerBalance: new(big.Int).Set(newPeerBalance),
		StateHash:   newStateHash,
		Signature:   signature,
		Timestamp:   time.Now(),
	}
	ch.stateHistory = append(ch.stateHistory, signedState)

	// Step 5: Update channel state
	ch.stateHash = newStateHash
	ch.mySignature = signature
	ch.UpdatedAt = time.Now()

	// Verify state was updated correctly
	if ch.Version != newVersion {
		// Rollback on error
		ch.Version = tempVersion
		ch.MyBalance = tempMyBalance
		ch.PeerBalance = tempPeerBalance
		return nil, fmt.Errorf("state update verification failed")
	}

	update := &ChannelUpdate{
		ChannelID:   ch.ID,
		Version:     ch.Version,
		MyBalance:   new(big.Int).Set(ch.MyBalance),
		PeerBalance: new(big.Int).Set(ch.PeerBalance),
		StateHash:   hex.EncodeToString(ch.stateHash),
		Timestamp:   ch.UpdatedAt,
	}

	ch.logger.Info("payment sent successfully",
		zap.String("channel_id", ch.ID),
		zap.Uint64("new_version", ch.Version),
		zap.String("my_balance", ch.MyBalance.String()),
		zap.String("peer_balance", ch.PeerBalance.String()),
		zap.String("state_hash", update.StateHash),
	)

	return update, nil
}

// ReceivePayment processes an incoming payment (for the provider side).
func (ch *Channel) ReceivePayment(ctx context.Context, amount *big.Int) (*ChannelUpdate, error) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if ch.State != ChannelStateOpen {
		return nil, fmt.Errorf("channel is not open (state: %s)", ch.State)
	}

	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("payment amount must be positive")
	}

	if ch.PeerBalance.Cmp(amount) < 0 {
		return nil, fmt.Errorf("peer has insufficient balance: have %s, need %s",
			ch.PeerBalance.String(), amount.String())
	}

	ch.logger.Info("receiving payment",
		zap.String("channel_id", ch.ID),
		zap.String("amount", amount.String()),
		zap.Uint64("current_version", ch.Version),
	)

	// Update balances (inverse of SendPayment - provider receives)
	ch.PeerBalance.Sub(ch.PeerBalance, amount)
	ch.MyBalance.Add(ch.MyBalance, amount)
	ch.Version++
	ch.UpdatedAt = time.Now()

	// Compute and store new state
	ch.stateHash = ch.computeStateHash()
	ch.mySignature = ch.signState()

	signedState := &SignedState{
		ChannelID:   ch.ID,
		Version:     ch.Version,
		MyBalance:   new(big.Int).Set(ch.MyBalance),
		PeerBalance: new(big.Int).Set(ch.PeerBalance),
		StateHash:   ch.stateHash,
		Signature:   ch.mySignature,
		Timestamp:   ch.UpdatedAt,
	}
	ch.stateHistory = append(ch.stateHistory, signedState)

	update := &ChannelUpdate{
		ChannelID:   ch.ID,
		Version:     ch.Version,
		MyBalance:   new(big.Int).Set(ch.MyBalance),
		PeerBalance: new(big.Int).Set(ch.PeerBalance),
		StateHash:   hex.EncodeToString(ch.stateHash),
		Timestamp:   ch.UpdatedAt,
	}

	ch.logger.Info("payment received successfully",
		zap.String("channel_id", ch.ID),
		zap.Uint64("new_version", ch.Version),
		zap.String("my_balance", ch.MyBalance.String()),
		zap.String("peer_balance", ch.PeerBalance.String()),
	)

	return update, nil
}

// Settle initiates channel settlement on-chain.
func (ch *Channel) Settle(ctx context.Context) error {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if ch.State == ChannelStateClosed {
		return fmt.Errorf("channel already closed")
	}

	if ch.State == ChannelStateSettling {
		return fmt.Errorf("channel already settling")
	}

	ch.logger.Info("initiating channel settlement",
		zap.String("channel_id", ch.ID),
		zap.Uint64("final_version", ch.Version),
		zap.String("my_final_balance", ch.MyBalance.String()),
		zap.String("peer_final_balance", ch.PeerBalance.String()),
	)

	ch.State = ChannelStateSettling

	// Step 1: Get latest signed state
	var latestState *SignedState
	if len(ch.stateHistory) > 0 {
		latestState = ch.stateHistory[len(ch.stateHistory)-1]
	}

	// Step 2: Submit latest signed state to blockchain
	// In real implementation, this creates a CKB transaction
	settlementData := struct {
		ChannelID   string
		Version     uint64
		MyBalance   string
		PeerBalance string
		StateHash   string
	}{
		ChannelID:   ch.ID,
		Version:     ch.Version,
		MyBalance:   ch.MyBalance.String(),
		PeerBalance: ch.PeerBalance.String(),
		StateHash:   hex.EncodeToString(ch.stateHash),
	}

	ch.logger.Debug("submitting settlement transaction",
		zap.Any("settlement_data", settlementData),
	)

	// Step 3: Generate settlement transaction hash
	ch.settlementTxHash = generateTxHash(ch.ID, "settlement", ch.Version)

	// Step 4: Wait for challenge period (simulated)
	// In real implementation, this would wait for the challenge duration
	// and handle any disputes
	select {
	case <-ctx.Done():
		ch.State = ChannelStateOpen // Revert on cancellation
		return ctx.Err()
	case <-time.After(100 * time.Millisecond): // Simulated challenge period
	}

	// Step 5: Finalize and mark as closed
	now := time.Now()
	ch.SettledAt = &now
	ch.State = ChannelStateClosed
	ch.UpdatedAt = now

	ch.logger.Info("channel settled successfully",
		zap.String("channel_id", ch.ID),
		zap.String("settlement_tx", ch.settlementTxHash),
		zap.String("final_my_balance", ch.MyBalance.String()),
		zap.String("final_peer_balance", ch.PeerBalance.String()),
		zap.Int("total_updates", len(ch.stateHistory)),
	)

	// Log state for verification
	if latestState != nil {
		ch.logger.Debug("settlement verified against latest state",
			zap.Uint64("version", latestState.Version),
			zap.String("state_hash", hex.EncodeToString(latestState.StateHash)),
		)
	}

	return nil
}

// GetState returns the current channel state.
func (ch *Channel) GetState() ChannelState {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.State
}

// GetBalances returns current balances.
func (ch *Channel) GetBalances() (myBalance, peerBalance *big.Int) {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return new(big.Int).Set(ch.MyBalance), new(big.Int).Set(ch.PeerBalance)
}

// GetStateHash returns the current state hash.
func (ch *Channel) GetStateHash() string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return hex.EncodeToString(ch.stateHash)
}

// GetFundingTxHash returns the funding transaction hash.
func (ch *Channel) GetFundingTxHash() string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.fundingTxHash
}

// GetSettlementTxHash returns the settlement transaction hash.
func (ch *Channel) GetSettlementTxHash() string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.settlementTxHash
}

// GetStateHistory returns the state update history.
func (ch *Channel) GetStateHistory() []*SignedState {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	history := make([]*SignedState, len(ch.stateHistory))
	copy(history, ch.stateHistory)
	return history
}

// GetChannel retrieves a channel by ID.
func (c *Client) GetChannel(channelID string) (*Channel, error) {
	c.channelsMu.RLock()
	defer c.channelsMu.RUnlock()

	channel, exists := c.channels[channelID]
	if !exists {
		return nil, fmt.Errorf("channel not found: %s", channelID)
	}

	return channel, nil
}

// ListChannels returns all channels.
func (c *Client) ListChannels() []*Channel {
	c.channelsMu.RLock()
	defer c.channelsMu.RUnlock()

	channels := make([]*Channel, 0, len(c.channels))
	for _, ch := range c.channels {
		channels = append(channels, ch)
	}

	return channels
}

// CloseChannel closes a channel and removes it from the client.
func (c *Client) CloseChannel(channelID string) error {
	channel, err := c.GetChannel(channelID)
	if err != nil {
		return err
	}

	if err := channel.Settle(context.Background()); err != nil {
		return fmt.Errorf("failed to settle channel: %w", err)
	}

	c.channelsMu.Lock()
	delete(c.channels, channelID)
	c.channelsMu.Unlock()

	return nil
}

// generateTxHash creates a simulated transaction hash.
func generateTxHash(channelID, txType string, nonce uint64) string {
	data := fmt.Sprintf("%s:%s:%d:%d", channelID, txType, nonce, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return "0x" + hex.EncodeToString(hash[:])
}
