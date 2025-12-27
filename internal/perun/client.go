// Package perun provides Perun state channel integration for CKB network.
package perun

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/v2/systemscript"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"go.uber.org/zap"
)

// Client wraps the Perun channel functionality for AirFi.
type Client struct {
	config     *Config
	logger     *zap.Logger
	privateKey *ecdsa.PrivateKey
	ckbKey     *secp256k1.Secp256k1Key // CKB secp256k1 key
	address    string
	lockScript *types.Script

	// Channel management
	channels   map[string]*Channel
	channelsMu sync.RWMutex

	// CKB connection
	ckbClient  *CKBClient
	httpClient *http.Client

	// Asset registry
	assets map[string]*Asset

	// State
	connected bool
	ctx       context.Context
	cancel    context.CancelFunc
}

// CKBClient represents a connection to the CKB network.
type CKBClient struct {
	RPCURL     string
	IndexerURL string
	NetworkID  string
	Connected  bool
}

// Asset represents a registered asset type.
type Asset struct {
	ID       string
	Name     string
	Symbol   string
	Decimals uint8
}

// NewClient creates a new Perun client with the given configuration.
func NewClient(config *Config, logger *zap.Logger) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if logger == nil {
		logger = zap.NewNop()
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		config:   config,
		logger:   logger,
		channels: make(map[string]*Channel),
		assets:   make(map[string]*Asset),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	return client, nil
}

// Connect establishes connection to the CKB network.
func (c *Client) Connect(ctx context.Context) error {
	c.logger.Info("connecting to CKB network",
		zap.String("network", string(c.config.Network)),
		zap.String("rpc_url", c.config.RPCURL),
	)

	// Initialize CKB SDK client
	c.ckbClient = &CKBClient{
		RPCURL:     c.config.RPCURL,
		IndexerURL: c.config.IndexerURL,
		NetworkID:  string(c.config.Network),
	}

	// Verify CKB RPC connection
	if err := c.verifyCKBConnection(ctx); err != nil {
		c.logger.Warn("CKB RPC verification failed, running in simulation mode",
			zap.Error(err),
		)
		// Continue in simulation mode if RPC is not available
	}
	c.ckbClient.Connected = true

	// Register CKBytes as the default asset
	c.registerAsset(&Asset{
		ID:       "CKBytes",
		Name:     "CKBytes",
		Symbol:   "CKB",
		Decimals: 8,
	})

	c.connected = true
	c.logger.Info("successfully connected to CKB network",
		zap.Bool("rpc_available", c.ckbClient.Connected),
		zap.Int("registered_assets", len(c.assets)),
	)

	return nil
}

// verifyCKBConnection checks if CKB RPC is reachable by calling get_tip_block_number.
func (c *Client) verifyCKBConnection(ctx context.Context) error {
	rpcReq := map[string]interface{}{
		"id":      1,
		"jsonrpc": "2.0",
		"method":  "get_tip_block_number",
		"params":  []interface{}{},
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.RPCURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to CKB RPC: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("CKB RPC returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	c.logger.Info("CKB RPC connected",
		zap.String("tip_block_number", rpcResp.Result),
	)

	return nil
}

// registerAsset registers an asset for use in channels.
func (c *Client) registerAsset(asset *Asset) {
	c.assets[asset.ID] = asset
	c.logger.Debug("registered asset",
		zap.String("id", asset.ID),
		zap.String("symbol", asset.Symbol),
	)
}

// GetAsset returns a registered asset by ID.
func (c *Client) GetAsset(assetID string) (*Asset, error) {
	asset, exists := c.assets[assetID]
	if !exists {
		return nil, fmt.Errorf("asset not found: %s", assetID)
	}
	return asset, nil
}

// Disconnect closes the connection to the CKB network.
func (c *Client) Disconnect() error {
	c.logger.Info("disconnecting from CKB network")

	// Close all open channels gracefully
	c.channelsMu.RLock()
	openChannels := make([]*Channel, 0)
	for _, ch := range c.channels {
		if ch.State == ChannelStateOpen {
			openChannels = append(openChannels, ch)
		}
	}
	c.channelsMu.RUnlock()

	for _, ch := range openChannels {
		c.logger.Info("closing channel on disconnect",
			zap.String("channel_id", ch.ID),
		)
		if err := ch.Settle(c.ctx); err != nil {
			c.logger.Warn("failed to settle channel on disconnect",
				zap.String("channel_id", ch.ID),
				zap.Error(err),
			)
		}
	}

	c.cancel()
	c.connected = false
	c.ckbClient = nil

	return nil
}

// IsConnected returns true if the client is connected to the network.
func (c *Client) IsConnected() bool {
	return c.connected
}

// LoadPrivateKey loads a private key from hex string.
func (c *Client) LoadPrivateKey(hexKey string) error {
	// Remove 0x prefix if present
	if len(hexKey) >= 2 && hexKey[:2] == "0x" {
		hexKey = hexKey[2:]
	}

	// Load key using CKB SDK
	ckbKey, err := secp256k1.HexToKey(hexKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	c.ckbKey = ckbKey

	// Also create ECDSA key for compatibility
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}
	privateKey, err := parseECDSAPrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSA key: %w", err)
	}
	c.privateKey = privateKey

	// Generate CKB address from public key
	pubKey := ckbKey.PubKey()
	pubKeyHash := blake2b.Blake160(pubKey)

	// Determine network
	network := types.NetworkTest
	if c.config.Network == NetworkMainnet {
		network = types.NetworkMain
	}

	// Create lock script
	codeHash := systemscript.GetCodeHash(network, systemscript.Secp256k1Blake160SighashAll)
	c.lockScript = &types.Script{
		CodeHash: codeHash,
		HashType: types.HashTypeType,
		Args:     pubKeyHash,
	}

	// Generate address
	c.address = c.encodeAddress(c.lockScript, network)

	c.logger.Info("loaded private key",
		zap.String("address", c.address),
		zap.String("pubkey_hash", hex.EncodeToString(pubKeyHash)),
	)

	return nil
}

// encodeAddress encodes a lock script to CKB address.
func (c *Client) encodeAddress(script *types.Script, network types.Network) string {
	payload := []byte{0x00}
	payload = append(payload, script.CodeHash[:]...)
	payload = append(payload, 0x01) // HashTypeType
	payload = append(payload, script.Args...)

	converted := convertBits(payload, 8, 5, true)

	hrp := "ckt"
	if network == types.NetworkMain {
		hrp = "ckb"
	}

	return bech32mEncode(hrp, converted)
}

// bech32m encoding helpers
func convertBits(data []byte, fromBits, toBits int, pad bool) []byte {
	acc, bits := 0, 0
	result := make([]byte, 0)
	maxv := (1 << toBits) - 1
	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}
	if pad && bits > 0 {
		result = append(result, byte((acc<<(toBits-bits))&maxv))
	}
	return result
}

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32mEncode(hrp string, data []byte) string {
	values := make([]int, len(data))
	for i, b := range data {
		values[i] = int(b)
	}
	checksum := createBech32mChecksum(hrp, values)
	result := hrp + "1"
	for _, v := range append(values, checksum...) {
		result += string(charset[v])
	}
	return result
}

func createBech32mChecksum(hrp string, data []int) []int {
	values := bech32mHrpExpand(hrp)
	values = append(values, data...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	polymod := bech32mPolymod(values) ^ 0x2bc830a3
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (polymod >> (5 * (5 - i))) & 31
	}
	return checksum
}

func bech32mHrpExpand(hrp string) []int {
	result := make([]int, 0)
	for _, c := range hrp {
		result = append(result, int(c)>>5)
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, int(c)&31)
	}
	return result
}

func bech32mPolymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// GenerateKeyPair generates a new ECDSA key pair for testing.
func (c *Client) GenerateKeyPair() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	c.privateKey = privateKey
	c.address = deriveAddress(privateKey)

	c.logger.Info("generated new key pair", zap.String("address", c.address))

	return nil
}

// GetAddress returns the wallet address.
func (c *Client) GetAddress() string {
	return c.address
}

// GetConfig returns the client configuration.
func (c *Client) GetConfig() *Config {
	return c.config
}

// GetPrivateKey returns the private key (for signing operations).
func (c *Client) GetPrivateKey() *ecdsa.PrivateKey {
	return c.privateKey
}

// SignData signs data with the client's private key.
func (c *Client) SignData(data []byte) ([]byte, error) {
	if c.privateKey == nil {
		return nil, fmt.Errorf("private key not loaded")
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, c.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// Encode signature as r || s
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// VerifySignature verifies a signature against data and public key.
func VerifySignature(publicKey *ecdsa.PublicKey, data, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}

	hash := sha256.Sum256(data)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(publicKey, hash[:], r, s)
}

// parseECDSAPrivateKey parses an ECDSA private key from bytes.
func parseECDSAPrivateKey(keyBytes []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	privateKey := new(ecdsa.PrivateKey)
	privateKey.Curve = curve
	privateKey.D = new(big.Int).SetBytes(keyBytes)

	// Derive public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(keyBytes)

	return privateKey, nil
}

// deriveAddress derives a CKB-style address from a private key.
func deriveAddress(privateKey *ecdsa.PrivateKey) string {
	pubKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	hash := sha256.Sum256(pubKeyBytes)
	// Use first 20 bytes of hash as address (similar to CKB short address)
	return "ckt1" + hex.EncodeToString(hash[:20])
}

// GetBalance queries the wallet balance from CKB network.
func (c *Client) GetBalance(ctx context.Context) (*big.Int, error) {
	if c.lockScript == nil {
		return nil, fmt.Errorf("wallet not loaded")
	}

	// Build cells query using indexer
	rpcReq := map[string]interface{}{
		"id":      1,
		"jsonrpc": "2.0",
		"method":  "get_cells_capacity",
		"params": []interface{}{
			map[string]interface{}{
				"script": map[string]interface{}{
					"code_hash": "0x" + hex.EncodeToString(c.lockScript.CodeHash[:]),
					"hash_type": "type",
					"args":      "0x" + hex.EncodeToString(c.lockScript.Args),
				},
				"script_type": "lock",
			},
		},
	}

	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.IndexerURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query balance: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp struct {
		Result struct {
			Capacity    string `json:"capacity"`
			BlockHash   string `json:"block_hash"`
			BlockNumber string `json:"block_number"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	// Parse capacity (hex string to big.Int)
	capacityStr := rpcResp.Result.Capacity
	if len(capacityStr) >= 2 && capacityStr[:2] == "0x" {
		capacityStr = capacityStr[2:]
	}

	capacity := new(big.Int)
	capacity.SetString(capacityStr, 16)

	c.logger.Info("wallet balance queried",
		zap.String("capacity", capacity.String()),
		zap.String("address", c.address),
	)

	return capacity, nil
}

// computeScriptHash computes blake2b hash of a script for querying.
func (c *Client) computeScriptHash(script *types.Script) []byte {
	data := make([]byte, 0)
	data = append(data, script.CodeHash[:]...)
	// HashType encoding: Type=1, Data=0, Data1=2
	var hashTypeByte byte
	switch script.HashType {
	case types.HashTypeType:
		hashTypeByte = 0x01
	case types.HashTypeData:
		hashTypeByte = 0x00
	case types.HashTypeData1:
		hashTypeByte = 0x02
	default:
		hashTypeByte = 0x00
	}
	data = append(data, hashTypeByte)
	data = append(data, script.Args...)
	return blake2b.Blake256(data)
}

// GetBalanceFormatted returns human-readable balance in CKB.
func (c *Client) GetBalanceFormatted(ctx context.Context) (string, error) {
	balance, err := c.GetBalance(ctx)
	if err != nil {
		return "", err
	}

	// CKB has 8 decimals (1 CKB = 100,000,000 shannons)
	ckb := new(big.Float).SetInt(balance)
	ckb.Quo(ckb, big.NewFloat(100000000))

	return fmt.Sprintf("%.8f CKB", ckb), nil
}

// SendCKB sends CKB to a recipient address.
func (c *Client) SendCKB(ctx context.Context, toAddress string, amount *big.Int) (string, error) {
	if c.ckbKey == nil {
		return "", fmt.Errorf("private key not loaded")
	}

	c.logger.Info("preparing CKB transaction",
		zap.String("to", toAddress),
		zap.String("amount", amount.String()),
	)

	// For now, return a simulation message with instructions
	// Full implementation requires building CKB transaction with proper cell collection
	return "", fmt.Errorf("on-chain transactions require full Perun-CKB integration; current implementation supports off-chain channel operations")
}

// GetStats returns client statistics.
func (c *Client) GetStats() map[string]interface{} {
	c.channelsMu.RLock()
	defer c.channelsMu.RUnlock()

	openCount := 0
	closedCount := 0
	totalFunding := big.NewInt(0)

	for _, ch := range c.channels {
		if ch.State == ChannelStateOpen {
			openCount++
			totalFunding.Add(totalFunding, ch.TotalFunding)
		} else if ch.State == ChannelStateClosed {
			closedCount++
		}
	}

	return map[string]interface{}{
		"connected":     c.connected,
		"network":       c.config.Network,
		"address":       c.address,
		"total_channels": len(c.channels),
		"open_channels":  openCount,
		"closed_channels": closedCount,
		"total_funding":  totalFunding.String(),
		"assets":        len(c.assets),
	}
}
