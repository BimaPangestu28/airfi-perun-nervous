// Package perun provides Perun state channel integration for CKB network.
package perun

import (
	"time"
)

// NetworkType represents the CKB network type.
type NetworkType string

const (
	// NetworkTestnet represents the CKB Testnet (Pudge).
	NetworkTestnet NetworkType = "testnet"
	// NetworkMainnet represents the CKB Mainnet (Lina).
	NetworkMainnet NetworkType = "mainnet"
	// NetworkDevnet represents a local development network.
	NetworkDevnet NetworkType = "devnet"
)

// Config holds the configuration for Perun channel operations.
type Config struct {
	// CKB network configuration
	Network    NetworkType
	RPCURL     string
	IndexerURL string

	// Channel configuration
	ChannelTimeout    time.Duration
	FundingTimeout    time.Duration
	SettlementTimeout time.Duration

	// Wallet configuration
	PrivateKeyPath string
	WalletAddress  string

	// Asset configuration
	AssetID string // CKBytes asset identifier
}

// DefaultTestnetConfig returns the default configuration for CKB Testnet.
func DefaultTestnetConfig() *Config {
	return &Config{
		Network:           NetworkTestnet,
		RPCURL:            "https://testnet.ckb.dev/rpc",
		IndexerURL:        "https://testnet.ckb.dev/indexer",
		ChannelTimeout:    1 * time.Hour,
		FundingTimeout:    10 * time.Minute,
		SettlementTimeout: 30 * time.Minute,
		AssetID:           "CKBytes",
	}
}

// DefaultDevnetConfig returns the default configuration for local devnet.
func DefaultDevnetConfig() *Config {
	return &Config{
		Network:           NetworkDevnet,
		RPCURL:            "http://localhost:8114",
		IndexerURL:        "http://localhost:8116",
		ChannelTimeout:    1 * time.Hour,
		FundingTimeout:    5 * time.Minute,
		SettlementTimeout: 10 * time.Minute,
		AssetID:           "CKBytes",
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.RPCURL == "" {
		return ErrInvalidConfig("RPC URL is required")
	}
	if c.ChannelTimeout <= 0 {
		return ErrInvalidConfig("channel timeout must be positive")
	}
	return nil
}

// ConfigError represents a configuration error.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return "perun config error: " + e.Message
}

// ErrInvalidConfig creates a new configuration error.
func ErrInvalidConfig(message string) error {
	return &ConfigError{Message: message}
}
