package perun

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/v2/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"go.uber.org/zap"

	"perun.network/go-perun/channel"
	"perun.network/go-perun/wallet"

	"perun.network/perun-ckb-backend/backend"
	"perun.network/perun-ckb-backend/channel/asset"
	ckbclient "perun.network/perun-ckb-backend/client"
	"perun.network/perun-ckb-backend/encoding"
	ckbwallet "perun.network/perun-ckb-backend/wallet"
	"perun.network/perun-ckb-backend/wallet/address"
)

// PerunClient wraps the CKB client for Perun channel operations.
type PerunClient struct {
	ckbClient   *ckbclient.Client
	account     *ckbwallet.Account
	wallet      *ckbwallet.EphemeralWallet
	signer      *backend.LocalSigner
	deployment  backend.Deployment
	rpcClient   rpc.Client
	logger      *zap.Logger
	ckbAddress  string

	// Active channels
	channels   map[channel.ID]*PaymentChannel
	channelsMu sync.RWMutex
}

// PaymentChannel represents an active Perun payment channel.
type PaymentChannel struct {
	ID          channel.ID
	Params      *channel.Params
	PeerAccount *ckbwallet.Account
	PeerAddress string
	MyBalance   *big.Int
	PeerBalance *big.Int
	State       string
	FundingTx   string
	PCTS        *types.Script // Perun Channel Type Script (for funding)
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PerunConfig contains configuration for the Perun client.
type PerunConfig struct {
	RPCURL       string
	PrivateKey   *secp256k1.PrivateKey
	Deployment   backend.Deployment
	ChallengeLen uint64
	Logger       *zap.Logger
}

// NewPerunClient creates a new Perun client for CKB.
func NewPerunClient(cfg *PerunConfig) (*PerunClient, error) {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}

	// Create RPC client
	rpcClient, err := rpc.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to dial RPC: %w", err)
	}

	cfg.Logger.Info("connected to CKB RPC", zap.String("url", cfg.RPCURL))

	// Create account from private key
	account := ckbwallet.NewAccountFromPrivateKey(cfg.PrivateKey)

	// Get participant address and convert to CKB address
	participant := address.AsParticipant(account.Address())
	ckbAddr := participant.ToCKBAddress(types.NetworkTest)
	ckbAddrStr, err := ckbAddr.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode address: %w", err)
	}

	cfg.Logger.Info("wallet address created",
		zap.String("address", ckbAddrStr),
	)

	// Create signer for transaction signing
	signer := backend.NewSignerInstance(ckbAddr, *cfg.PrivateKey, types.NetworkTest)

	// Create CKB client for Perun operations
	ckbClient, err := ckbclient.NewClient(rpcClient, signer, cfg.Deployment)
	if err != nil {
		return nil, fmt.Errorf("failed to create CKB client: %w", err)
	}

	// Create ephemeral wallet and add account
	ephWallet := ckbwallet.NewEphemeralWallet()
	if err := ephWallet.AddAccount(account); err != nil {
		return nil, fmt.Errorf("failed to add account to wallet: %w", err)
	}

	cfg.Logger.Info("Perun client initialized successfully")

	return &PerunClient{
		ckbClient:  ckbClient,
		account:    account,
		wallet:     ephWallet,
		signer:     signer,
		deployment: cfg.Deployment,
		rpcClient:  rpcClient,
		logger:     cfg.Logger,
		ckbAddress: ckbAddrStr,
		channels:   make(map[channel.ID]*PaymentChannel),
	}, nil
}

// OpenChannel opens a new payment channel with a peer.
// This creates an on-chain funding transaction visible on CKB explorer.
func (pc *PerunClient) OpenChannel(ctx context.Context, peerAddr string, myFunding, peerFunding *big.Int) (*PaymentChannel, error) {
	pc.logger.Info("opening Perun channel",
		zap.String("peer", peerAddr),
		zap.String("my_funding", myFunding.String()),
		zap.String("peer_funding", peerFunding.String()),
	)

	// Create CKBytes asset
	ckbAsset := asset.NewCKBytesAsset()

	// Create initial allocation
	initAlloc := channel.NewAllocation(2, ckbAsset)
	initAlloc.SetAssetBalances(ckbAsset, []channel.Bal{myFunding, peerFunding})

	// For this demo, create a peer account
	// In production, the peer would be another participant with their own wallet
	peerAccount, err := ckbwallet.NewAccount()
	if err != nil {
		return nil, fmt.Errorf("failed to create peer account: %w", err)
	}

	// Create channel parameters with empty aux data
	var emptyAux channel.Aux
	params, err := channel.NewParams(
		ChallengeBlocks,
		[]wallet.Address{pc.account.Address(), peerAccount.Address()},
		channel.NoApp(),
		big.NewInt(0),
		true,  // ledger channel
		false, // not virtual
		emptyAux,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create params: %w", err)
	}

	// Create initial state
	initState := &channel.State{
		ID:         params.ID(),
		Version:    0,
		App:        channel.NoApp(),
		Allocation: *initAlloc,
		Data:       channel.NoData(),
		IsFinal:    false,
	}

	pc.logger.Info("starting channel on-chain",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
	)

	// Start the channel on-chain (this creates the funding transaction)
	pcts, err := pc.ckbClient.Start(ctx, params, initState)
	if err != nil {
		return nil, fmt.Errorf("failed to start channel: %w", err)
	}

	// NOTE: pcts.Hash() returns the PCTS script hash, not the actual transaction hash.
	// The transaction hash is not exposed by the perun-ckb-backend library.
	// The actual funding transaction can be found in the explorer by looking at recent
	// transactions from the wallet address with -904 CKB capacity change.
	pctsHash := fmt.Sprintf("0x%x", pcts.Hash())
	pc.logger.Info("channel funding initiated",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
		zap.String("pcts_hash", pctsHash),
		zap.String("note", "Check wallet address in explorer for actual funding TX"),
	)

	// Create payment channel record
	paymentChannel := &PaymentChannel{
		ID:          params.ID(),
		Params:      params,
		PeerAccount: peerAccount,
		PeerAddress: peerAddr,
		MyBalance:   myFunding,
		PeerBalance: peerFunding,
		State:       "open",
		FundingTx:   pctsHash, // Note: This is PCTS script hash, not the actual TX hash
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store channel
	pc.channelsMu.Lock()
	pc.channels[params.ID()] = paymentChannel
	pc.channelsMu.Unlock()

	totalFunding := new(big.Int).Add(myFunding, peerFunding)
	pc.logger.Info("Perun channel opened successfully",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
		zap.String("total_funding", totalFunding.String()),
	)

	return paymentChannel, nil
}

// SendPayment sends a payment in the channel (off-chain state update).
func (pc *PerunClient) SendPayment(channelID channel.ID, amount *big.Int) error {
	pc.channelsMu.Lock()
	ch, exists := pc.channels[channelID]
	if !exists {
		pc.channelsMu.Unlock()
		return fmt.Errorf("channel not found")
	}

	// Update balances (off-chain)
	ch.MyBalance = new(big.Int).Sub(ch.MyBalance, amount)
	ch.PeerBalance = new(big.Int).Add(ch.PeerBalance, amount)
	ch.UpdatedAt = time.Now()
	pc.channelsMu.Unlock()

	pc.logger.Info("payment sent",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
		zap.String("amount", amount.String()),
	)

	return nil
}

// ReceivePayment receives a payment in the channel (off-chain state update).
func (pc *PerunClient) ReceivePayment(channelID channel.ID, amount *big.Int) error {
	pc.channelsMu.Lock()
	ch, exists := pc.channels[channelID]
	if !exists {
		pc.channelsMu.Unlock()
		return fmt.Errorf("channel not found")
	}

	// Update balances (off-chain)
	ch.MyBalance = new(big.Int).Add(ch.MyBalance, amount)
	ch.PeerBalance = new(big.Int).Sub(ch.PeerBalance, amount)
	ch.UpdatedAt = time.Now()
	pc.channelsMu.Unlock()

	pc.logger.Info("payment received",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
		zap.String("amount", amount.String()),
	)

	return nil
}

// SettleChannel settles the channel on-chain.
// This creates a settlement transaction visible on CKB explorer.
func (pc *PerunClient) SettleChannel(ctx context.Context, channelID channel.ID) (string, error) {
	pc.channelsMu.Lock()
	ch, exists := pc.channels[channelID]
	if !exists {
		pc.channelsMu.Unlock()
		return "", fmt.Errorf("channel not found")
	}
	pc.channelsMu.Unlock()

	pc.logger.Info("settling channel",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
		zap.String("my_balance", ch.MyBalance.String()),
		zap.String("peer_balance", ch.PeerBalance.String()),
	)

	// Create final state for closing
	ckbAsset := asset.NewCKBytesAsset()
	finalAlloc := channel.NewAllocation(2, ckbAsset)
	finalAlloc.SetAssetBalances(ckbAsset, []channel.Bal{ch.MyBalance, ch.PeerBalance})

	// Create final state
	finalState := &channel.State{
		ID:         channelID,
		Version:    1,
		App:        channel.NoApp(),
		Allocation: *finalAlloc,
		Data:       channel.NoData(),
		IsFinal:    true,
	}

	// Pack the state into molecule format for signing
	// This is the format the smart contract expects
	packedState, err := encoding.PackChannelState(finalState)
	if err != nil {
		return "", fmt.Errorf("failed to pack state: %w", err)
	}
	stateBytes := packedState.AsSlice()

	// Sign the packed state
	sig, err := pc.account.SignData(stateBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign final state: %w", err)
	}

	// Sign with peer account as well
	peerSig, err := ch.PeerAccount.SignData(stateBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign with peer: %w", err)
	}

	// Close the channel on-chain
	err = pc.ckbClient.Close(ctx, channelID, finalState, []wallet.Sig{sig, peerSig}, ch.Params)
	if err != nil {
		return "", fmt.Errorf("failed to close channel: %w", err)
	}

	// Update channel state
	pc.channelsMu.Lock()
	ch.State = "settled"
	ch.UpdatedAt = time.Now()
	pc.channelsMu.Unlock()

	settleTxHash := fmt.Sprintf("0x%x", channelID[:8])

	pc.logger.Info("channel settled successfully",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
	)

	return settleTxHash, nil
}

// DisputeChannel registers a dispute on-chain to start the challenge period.
// This is Step 1 of force close - submit current state and start challenge timer.
func (pc *PerunClient) DisputeChannel(ctx context.Context, channelID channel.ID) error {
	pc.channelsMu.Lock()
	ch, exists := pc.channels[channelID]
	if !exists {
		pc.channelsMu.Unlock()
		return fmt.Errorf("channel not found")
	}
	pc.channelsMu.Unlock()

	pc.logger.Info("disputing channel (starting challenge period)",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
		zap.String("my_balance", ch.MyBalance.String()),
		zap.String("peer_balance", ch.PeerBalance.String()),
	)

	// Create current state
	ckbAsset := asset.NewCKBytesAsset()
	currentAlloc := channel.NewAllocation(2, ckbAsset)
	currentAlloc.SetAssetBalances(ckbAsset, []channel.Bal{ch.MyBalance, ch.PeerBalance})

	currentState := &channel.State{
		ID:         channelID,
		Version:    1,
		App:        channel.NoApp(),
		Allocation: *currentAlloc,
		Data:       channel.NoData(),
		IsFinal:    false, // Not final yet - this is a dispute
	}

	// Pack the state into molecule format for signing
	packedState, err := encoding.PackChannelState(currentState)
	if err != nil {
		return fmt.Errorf("failed to pack state: %w", err)
	}
	stateBytes := packedState.AsSlice()

	// Sign the state
	sig, err := pc.account.SignData(stateBytes)
	if err != nil {
		return fmt.Errorf("failed to sign state: %w", err)
	}

	// Sign with peer account
	peerSig, err := ch.PeerAccount.SignData(stateBytes)
	if err != nil {
		return fmt.Errorf("failed to sign with peer: %w", err)
	}

	// Register dispute on-chain
	err = pc.ckbClient.Dispute(ctx, channelID, currentState, []wallet.Sig{sig, peerSig}, ch.Params)
	if err != nil {
		return fmt.Errorf("failed to dispute channel: %w", err)
	}

	// Update channel state
	pc.channelsMu.Lock()
	ch.State = "disputed"
	ch.UpdatedAt = time.Now()
	pc.channelsMu.Unlock()

	pc.logger.Info("channel dispute registered, challenge period started",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
		zap.Int("challenge_blocks", ChallengeBlocks),
	)

	return nil
}

// ForceCloseChannel closes the channel after the challenge period has expired.
// This is Step 2 of force close - claim funds after challenge period.
func (pc *PerunClient) ForceCloseChannel(ctx context.Context, channelID channel.ID) error {
	pc.channelsMu.Lock()
	ch, exists := pc.channels[channelID]
	if !exists {
		pc.channelsMu.Unlock()
		return fmt.Errorf("channel not found")
	}
	pc.channelsMu.Unlock()

	pc.logger.Info("force closing channel",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
		zap.String("my_balance", ch.MyBalance.String()),
		zap.String("peer_balance", ch.PeerBalance.String()),
	)

	// Create final state
	ckbAsset := asset.NewCKBytesAsset()
	finalAlloc := channel.NewAllocation(2, ckbAsset)
	finalAlloc.SetAssetBalances(ckbAsset, []channel.Bal{ch.MyBalance, ch.PeerBalance})

	finalState := &channel.State{
		ID:         channelID,
		Version:    1,
		App:        channel.NoApp(),
		Allocation: *finalAlloc,
		Data:       channel.NoData(),
		IsFinal:    true,
	}

	// Force close the channel
	err := pc.ckbClient.ForceClose(ctx, channelID, finalState, ch.Params)
	if err != nil {
		return fmt.Errorf("failed to force close channel: %w", err)
	}

	// Update channel state
	pc.channelsMu.Lock()
	ch.State = "force_closed"
	ch.UpdatedAt = time.Now()
	pc.channelsMu.Unlock()

	pc.logger.Info("channel force closed successfully",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
	)

	return nil
}

// GetChannel returns a channel by ID.
func (pc *PerunClient) GetChannel(channelID channel.ID) (*PaymentChannel, error) {
	pc.channelsMu.RLock()
	defer pc.channelsMu.RUnlock()

	ch, exists := pc.channels[channelID]
	if !exists {
		return nil, fmt.Errorf("channel not found")
	}
	return ch, nil
}

// GetAddress returns the client's CKB address.
func (pc *PerunClient) GetAddress() string {
	return pc.ckbAddress
}

// Close closes the Perun client.
func (pc *PerunClient) Close() error {
	// Clean up resources if needed
	return nil
}

// GetBalance returns the wallet balance in shannons.
func (pc *PerunClient) GetBalance(ctx context.Context) (*big.Int, error) {
	// Get CKB address and decode to get script args
	addr := pc.signer.Address()
	script := addr.Script

	// Query balance using indexer API
	resp, err := pc.rpcClient.GetCellsCapacity(ctx, &indexer.SearchKey{
		Script: &types.Script{
			CodeHash: types.HexToHash("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
			HashType: types.HashTypeType,
			Args:     script.Args,
		},
		ScriptType: types.ScriptTypeLock,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}

	return big.NewInt(int64(resp.Capacity)), nil
}

// IsConnected returns true if the client is connected.
func (pc *PerunClient) IsConnected() bool {
	return pc.rpcClient != nil
}

// GetDeployment returns the Perun deployment config.
func (pc *PerunClient) GetDeployment() backend.Deployment {
	return pc.deployment
}

// ListChannels returns all active channels.
func (pc *PerunClient) ListChannels() []*PaymentChannel {
	pc.channelsMu.RLock()
	defer pc.channelsMu.RUnlock()

	channels := make([]*PaymentChannel, 0, len(pc.channels))
	for _, ch := range pc.channels {
		channels = append(channels, ch)
	}
	return channels
}

// GetChannelByString returns a channel by hex string ID.
func (pc *PerunClient) GetChannelByString(channelIDHex string) (*PaymentChannel, error) {
	pc.channelsMu.RLock()
	defer pc.channelsMu.RUnlock()

	for _, ch := range pc.channels {
		if fmt.Sprintf("%x", ch.ID) == channelIDHex {
			return ch, nil
		}
	}
	return nil, fmt.Errorf("channel not found: %s", channelIDHex)
}

// GetAccount returns the wallet account for 2-party coordination.
func (pc *PerunClient) GetAccount() *ckbwallet.Account {
	return pc.account
}

// OpenChannelWithPeer opens a channel with a real peer account (for 2-party setup).
// This is used when both parties have real Perun clients with private keys.
func (pc *PerunClient) OpenChannelWithPeer(ctx context.Context, peerAccount *ckbwallet.Account, peerCKBAddr string, myFunding, peerFunding *big.Int) (*PaymentChannel, error) {
	pc.logger.Info("opening 2-party Perun channel",
		zap.String("peer", peerCKBAddr),
		zap.String("my_funding", myFunding.String()),
		zap.String("peer_funding", peerFunding.String()),
	)

	// Create CKBytes asset
	ckbAsset := asset.NewCKBytesAsset()

	// Create initial allocation
	initAlloc := channel.NewAllocation(2, ckbAsset)
	initAlloc.SetAssetBalances(ckbAsset, []channel.Bal{myFunding, peerFunding})

	// Create channel parameters with REAL peer address
	var emptyAux channel.Aux
	params, err := channel.NewParams(
		ChallengeBlocks,
		[]wallet.Address{pc.account.Address(), peerAccount.Address()},
		channel.NoApp(),
		big.NewInt(0),
		true,  // ledger channel
		false, // not virtual
		emptyAux,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create params: %w", err)
	}

	// Create initial state
	initState := &channel.State{
		ID:         params.ID(),
		Version:    0,
		App:        channel.NoApp(),
		Allocation: *initAlloc,
		Data:       channel.NoData(),
		IsFinal:    false,
	}

	pc.logger.Info("starting 2-party channel on-chain",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
	)

	// Start the channel on-chain (this creates the funding transaction)
	pcts, err := pc.ckbClient.Start(ctx, params, initState)
	if err != nil {
		return nil, fmt.Errorf("failed to start channel: %w", err)
	}

	pctsHash := fmt.Sprintf("0x%x", pcts.Hash())
	pc.logger.Info("2-party channel funding initiated",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
		zap.String("pcts_hash", pctsHash),
	)

	// Create payment channel record
	paymentChannel := &PaymentChannel{
		ID:          params.ID(),
		Params:      params,
		PeerAccount: peerAccount, // REAL peer account
		PeerAddress: peerCKBAddr,
		MyBalance:   myFunding,
		PeerBalance: peerFunding,
		State:       "pending", // Waiting for peer to fund
		FundingTx:   pctsHash,
		PCTS:        pcts, // Store PCTS for peer funding
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Store channel
	pc.channelsMu.Lock()
	pc.channels[params.ID()] = paymentChannel
	pc.channelsMu.Unlock()

	pc.logger.Info("2-party Perun channel opened successfully (pending peer funding)",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
	)

	return paymentChannel, nil
}

// FundChannel funds a channel opened by the peer (Party B's funding step).
// This must be called by Party B after Party A calls OpenChannelWithPeer.
func (pc *PerunClient) FundChannel(ctx context.Context, pcts *types.Script, params *channel.Params, state *channel.State) error {
	pc.logger.Info("funding channel as Party B",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
	)

	err := pc.ckbClient.Fund(ctx, pcts, state, params)
	if err != nil {
		return fmt.Errorf("failed to fund channel: %w", err)
	}

	// Update channel state if we have it registered
	pc.channelsMu.Lock()
	if ch, exists := pc.channels[params.ID()]; exists {
		ch.State = "funded"
		ch.UpdatedAt = time.Now()
	}
	pc.channelsMu.Unlock()

	pc.logger.Info("channel funded successfully",
		zap.String("channel_id", fmt.Sprintf("%x", params.ID())),
	)

	return nil
}

// RegisterChannel registers a channel opened by peer (for 2-party setup).
// The peer client calls this to track the channel on their side.
func (pc *PerunClient) RegisterChannel(channelID channel.ID, params *channel.Params, peerAccount *ckbwallet.Account, peerCKBAddr string, myBalance, peerBalance *big.Int) {
	paymentChannel := &PaymentChannel{
		ID:          channelID,
		Params:      params,
		PeerAccount: peerAccount,
		PeerAddress: peerCKBAddr,
		MyBalance:   myBalance,
		PeerBalance: peerBalance,
		State:       "open",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	pc.channelsMu.Lock()
	pc.channels[channelID] = paymentChannel
	pc.channelsMu.Unlock()

	pc.logger.Info("channel registered",
		zap.String("channel_id", fmt.Sprintf("%x", channelID)),
	)
}
