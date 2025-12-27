package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/airfi/airfi-perun-nervous/internal/perun"
)

func main() {
	// Setup logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	// Load config
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read config", zap.Error(err))
	}

	// Get private key
	privateKeyHex := viper.GetString("ckb.private_key")
	if privateKeyHex == "" {
		logger.Fatal("host private key not configured")
	}

	// Remove 0x prefix if present
	if len(privateKeyHex) > 2 && privateKeyHex[:2] == "0x" {
		privateKeyHex = privateKeyHex[2:]
	}

	// Parse private key
	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		logger.Fatal("failed to decode private key", zap.Error(err))
	}
	privateKey := secp256k1.PrivKeyFromBytes(keyBytes)

	// Create Perun client config
	cfg := &perun.PerunConfig{
		RPCURL:     perun.TestnetRPCURL,
		PrivateKey: privateKey,
		Deployment: perun.GetTestnetDeployment(),
		Logger:     logger,
	}

	logger.Info("=== Testing Perun CKB Channel ===")
	logger.Info("RPC URL", zap.String("url", cfg.RPCURL))

	// Create Perun client
	logger.Info("Creating Perun client...")
	client, err := perun.NewPerunClient(cfg)
	if err != nil {
		logger.Fatal("failed to create Perun client", zap.Error(err))
	}
	defer client.Close()

	logger.Info("Perun client created",
		zap.String("address", client.GetAddress()),
	)

	// Test opening a channel
	logger.Info("=== Opening Perun Channel ===")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Funding amounts (in shannons - 1 CKB = 100,000,000 shannons)
	// Minimum funding needs to cover PFLS capacity (~73 CKB per participant due to script size)
	myFunding := big.NewInt(10000000000)   // 100 CKB
	peerFunding := big.NewInt(10000000000) // 100 CKB

	logger.Info("Channel parameters",
		zap.String("my_funding", fmt.Sprintf("%s shannons (%.2f CKB)", myFunding.String(), float64(myFunding.Int64())/100000000)),
		zap.String("peer_funding", fmt.Sprintf("%s shannons (%.2f CKB)", peerFunding.String(), float64(peerFunding.Int64())/100000000)),
	)

	// Open channel
	channel, err := client.OpenChannel(ctx, "guest-demo", myFunding, peerFunding)
	if err != nil {
		logger.Error("failed to open channel", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("=== Channel Opened Successfully! ===",
		zap.String("channel_id", fmt.Sprintf("%x", channel.ID)),
		zap.String("funding_tx", channel.FundingTx),
		zap.String("state", channel.State),
		zap.String("my_balance", channel.MyBalance.String()),
		zap.String("peer_balance", channel.PeerBalance.String()),
	)

	// Print explorer link
	fmt.Println("\n" + "═══════════════════════════════════════════════════════════════")
	fmt.Println("  CHANNEL CREATED ON CKB TESTNET!")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Channel ID: %x\n", channel.ID)
	fmt.Printf("  Funding TX: %s\n", channel.FundingTx)
	fmt.Println("\n  View on Explorer:")
	fmt.Printf("  https://pudge.explorer.nervos.org/transaction/%s\n", channel.FundingTx)
	fmt.Println("═══════════════════════════════════════════════════════════════\n")
}
