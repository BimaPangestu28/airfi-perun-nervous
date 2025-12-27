package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"go.uber.org/zap"

	gpclient "perun.network/go-perun/client"
	gpchannel "perun.network/go-perun/channel"
	gpwallet "perun.network/go-perun/wallet"
	gpwire "perun.network/go-perun/wire"

	"perun.network/perun-ckb-backend/channel/asset"

	"github.com/airfi/airfi-perun-nervous/internal/perun"
)

func main() {
	// Setup logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  AirFi Full go-perun Channel Test")
	fmt.Println("  Using proper 2-party protocol with automatic signing")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Create shared wire bus for communication
	bus := gpwire.NewLocalBus()

	// Host wallet (WiFi provider)
	hostPrivKeyHex := "5ba43817d0634ca9f1620b4f17874f366794f181cd0eb854ea7ff711093b26f3"
	hostKeyBytes, _ := hex.DecodeString(hostPrivKeyHex)
	hostPrivKey := secp256k1.PrivKeyFromBytes(hostKeyBytes)

	// Guest wallet (WiFi user)
	guestPrivKeyHex := "afa8e30da03b2dc13a8eccc2546d1d7a36c4a9bbdcdc3e94d18e44cb4eb73b41"
	guestKeyBytes, _ := hex.DecodeString(guestPrivKeyHex)
	guestPrivKey := secp256k1.PrivKeyFromBytes(guestKeyBytes)

	// Create Host channel client
	fmt.Println("\n  Creating Host channel client...")
	hostClient, err := perun.NewChannelClient(&perun.ChannelClientConfig{
		RPCURL:     perun.TestnetRPCURL,
		PrivateKey: hostPrivKey,
		Deployment: perun.GetTestnetDeployment(),
		Logger:     logger.Named("host"),
		WireBus:    bus,
	})
	if err != nil {
		logger.Fatal("failed to create Host client", zap.Error(err))
	}
	defer hostClient.Close()

	// Create Guest channel client
	fmt.Println("  Creating Guest channel client...")
	guestClient, err := perun.NewChannelClient(&perun.ChannelClientConfig{
		RPCURL:     perun.TestnetRPCURL,
		PrivateKey: guestPrivKey,
		Deployment: perun.GetTestnetDeployment(),
		Logger:     logger.Named("guest"),
		WireBus:    bus,
	})
	if err != nil {
		logger.Fatal("failed to create Guest client", zap.Error(err))
	}
	defer guestClient.Close()

	fmt.Printf("\n  Host Address:  %s\n", hostClient.GetAddress())
	fmt.Printf("  Guest Address: %s\n", guestClient.GetAddress())

	// Check balances
	ctx := context.Background()
	hostBalance, _ := hostClient.GetBalance(ctx)
	guestBalance, _ := guestClient.GetBalance(ctx)
	fmt.Printf("\n  Host Balance:  %.2f CKB\n", float64(hostBalance.Int64())/100000000)
	fmt.Printf("  Guest Balance: %.2f CKB\n", float64(guestBalance.Int64())/100000000)

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Step 1: Setup Proposal Handlers")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Channel to receive the opened channel on Host side
	hostChannelChan := make(chan *gpclient.Channel, 1)

	// Host handles incoming proposals
	hostClient.HandleProposals(&ProposalHandler{
		account:     hostClient.GetAccount(),
		channelChan: hostChannelChan,
		logger:      logger.Named("host-handler"),
	})

	fmt.Println("  ✅ Host is listening for channel proposals")

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Step 2: Guest Proposes Channel")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	guestFunding := big.NewInt(10000000000) // 100 CKB
	hostFunding := big.NewInt(10000000000)  // 100 CKB

	fmt.Printf("\n  Guest Funding: %.2f CKB\n", float64(guestFunding.Int64())/100000000)
	fmt.Printf("  Host Funding:  %.2f CKB\n", float64(hostFunding.Int64())/100000000)
	fmt.Println("\n  Proposing channel...")

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Guest proposes channel to Host
	guestChannel, err := guestClient.ProposeChannel(
		ctxTimeout,
		hostClient.GetWireAddress(),
		hostClient.GetAccount().Address(),
		guestFunding,
		hostFunding,
	)
	if err != nil {
		logger.Error("failed to propose channel", zap.Error(err))
		fmt.Printf("\n  ❌ Error: %v\n", err)
		return
	}

	// Wait for Host to accept and get the channel
	fmt.Println("  Waiting for Host to accept...")
	var hostChannel *gpclient.Channel
	select {
	case hostChannel = <-hostChannelChan:
		fmt.Println("  ✅ Host accepted the channel!")
	case <-time.After(3 * time.Minute):
		fmt.Println("  ❌ Timeout waiting for Host to accept")
		return
	}

	fmt.Printf("\n  Channel ID: %x\n", guestChannel.ID())
	fmt.Printf("  Guest Balance in Channel: %.2f CKB\n", float64(guestFunding.Int64())/100000000)
	fmt.Printf("  Host Balance in Channel:  %.2f CKB\n", float64(hostFunding.Int64())/100000000)

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Step 3: Guest Makes Payments (Off-chain with proper signing)")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// Simulate WiFi usage payments
	payments := []int64{
		100000000, // 1 CKB
		500000000, // 5 CKB
		200000000, // 2 CKB
	}

	for i, amount := range payments {
		paymentAmount := big.NewInt(amount)

		// Guest sends payment (this properly signs the state)
		err := guestClient.SendPayment(guestChannel, paymentAmount)
		if err != nil {
			logger.Error("payment failed", zap.Error(err))
			fmt.Printf("\n  ❌ Payment %d failed: %v\n", i+1, err)
			continue
		}

		fmt.Printf("\n  Payment %d: %.2f CKB → Host\n", i+1, float64(amount)/100000000)
	}

	// Show final channel state
	guestState := guestChannel.State()
	ckbAsset := asset.NewCKBytesAsset()
	guestBal := guestState.Allocation.Balance(guestChannel.Idx(), ckbAsset)
	hostBal := guestState.Allocation.Balance(1-guestChannel.Idx(), ckbAsset)

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Channel State After Payments")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("\n  Guest Balance: %.2f CKB\n", float64(guestBal.Int64())/100000000)
	fmt.Printf("  Host Balance:  %.2f CKB\n", float64(hostBal.Int64())/100000000)
	fmt.Printf("  Total Paid: %.2f CKB\n", float64(8*100000000)/100000000)

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Step 4: Settle Channel (On-chain)")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	fmt.Println("\n  Settling channel (properly signed state)...")

	// Guest settles the channel
	err = guestClient.SettleChannel(ctxTimeout, guestChannel)
	if err != nil {
		fmt.Printf("\n  ❌ Settlement Error: %v\n", err)

		// Also try settling from Host side
		fmt.Println("\n  Trying Host-side settlement...")
		err = hostClient.SettleChannel(ctxTimeout, hostChannel)
		if err != nil {
			fmt.Printf("  ❌ Host Settlement Error: %v\n", err)
		} else {
			fmt.Println("  ✅ Channel settled by Host!")
		}
	} else {
		fmt.Println("  ✅ Channel settled by Guest!")
	}

	// Check final on-chain balances
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("  Final On-Chain Balances")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	hostBalanceFinal, _ := hostClient.GetBalance(ctx)
	guestBalanceFinal, _ := guestClient.GetBalance(ctx)
	fmt.Printf("\n  Host Balance:  %.2f CKB (was %.2f)\n",
		float64(hostBalanceFinal.Int64())/100000000,
		float64(hostBalance.Int64())/100000000)
	fmt.Printf("  Guest Balance: %.2f CKB (was %.2f)\n",
		float64(guestBalanceFinal.Int64())/100000000,
		float64(guestBalance.Int64())/100000000)

	fmt.Println("\n  Check wallets in explorer:")
	fmt.Printf("  Host:  https://pudge.explorer.nervos.org/address/%s\n", hostClient.GetAddress())
	fmt.Printf("  Guest: https://pudge.explorer.nervos.org/address/%s\n", guestClient.GetAddress())
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// ProposalHandler handles incoming channel proposals.
type ProposalHandler struct {
	account     gpwallet.Account
	channelChan chan *gpclient.Channel
	logger      *zap.Logger
}

// HandleProposal handles a ledger channel proposal.
func (h *ProposalHandler) HandleProposal(proposal gpclient.ChannelProposal, responder *gpclient.ProposalResponder) {
	h.logger.Info("received channel proposal")

	// Type assert to LedgerChannelProposalMsg to call Accept
	ledgerProposal, ok := proposal.(*gpclient.LedgerChannelProposalMsg)
	if !ok {
		h.logger.Error("expected LedgerChannelProposalMsg")
		return
	}

	// Accept the proposal
	accept := ledgerProposal.Accept(h.account.Address(), gpclient.WithRandomNonce())

	ch, err := responder.Accept(context.Background(), accept)
	if err != nil {
		h.logger.Error("failed to accept proposal", zap.Error(err))
		return
	}

	h.logger.Info("accepted channel proposal",
		zap.String("channel_id", fmt.Sprintf("%x", ch.ID())),
	)

	// Send the channel to the main goroutine
	h.channelChan <- ch
}

// HandleUpdate handles incoming channel updates.
func (h *ProposalHandler) HandleUpdate(cur *gpchannel.State, next gpclient.ChannelUpdate, responder *gpclient.UpdateResponder) {
	h.logger.Info("received update proposal",
		zap.Uint64("version", next.State.Version),
	)

	// Accept all updates (in production, you'd verify the update)
	err := responder.Accept(context.Background())
	if err != nil {
		h.logger.Error("failed to accept update", zap.Error(err))
	}
}
