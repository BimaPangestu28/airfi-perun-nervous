package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/airfi/airfi-perun-nervous/internal/api"
	"github.com/airfi/airfi-perun-nervous/internal/perun"
	"github.com/airfi/airfi-perun-nervous/internal/session"
)

func main() {
	// Setup logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	logger.Info("=== AirFi Perun API Server ===")

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

	// Create Perun client
	logger.Info("Creating Perun client...")
	perunClient, err := perun.NewPerunClient(cfg)
	if err != nil {
		logger.Fatal("failed to create Perun client", zap.Error(err))
	}
	defer perunClient.Close()

	logger.Info("Perun client created",
		zap.String("address", perunClient.GetAddress()),
		zap.Bool("connected", perunClient.IsConnected()),
	)

	// Create session manager (minimal for testing)
	sessionStore := session.NewStore()
	sessionManager := session.NewManager(sessionStore, nil, nil, nil, logger)

	// Create Perun handler
	handler := api.NewPerunHandler(perunClient, sessionManager, logger)

	// Create router
	router := api.NewPerunRouter(handler)

	// Start server
	port := viper.GetString("server.port")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	server := &http.Server{
		Addr:    addr,
		Handler: router.Engine(),
	}

	// Handle shutdown gracefully
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("Shutting down server...")
		server.Close()
	}()

	logger.Info("Starting AirFi Perun API server",
		zap.String("address", addr),
		zap.String("wallet", perunClient.GetAddress()),
	)

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  AirFi Perun API Server - Real CKB Testnet Channels")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  Server: http://localhost%s\n", addr)
	fmt.Printf("  Wallet: %s\n", perunClient.GetAddress())
	fmt.Println("\n  API Endpoints:")
	fmt.Println("  GET  /health                 - Health check")
	fmt.Println("  GET  /api/v1/wallet          - Wallet status")
	fmt.Println("  GET  /api/v1/channels        - List channels")
	fmt.Println("  POST /api/v1/channels/open   - Open channel")
	fmt.Println("  POST /api/v1/channels/:id/send    - Send payment")
	fmt.Println("  POST /api/v1/channels/:id/receive - Receive payment")
	fmt.Println("  POST /api/v1/channels/:id/settle  - Settle channel")
	fmt.Println("  GET  /api/v1/channels/:id    - Get channel")
	fmt.Println("═══════════════════════════════════════════════════════════════\n")

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal("server error", zap.Error(err))
	}

	logger.Info("Server stopped")
}
