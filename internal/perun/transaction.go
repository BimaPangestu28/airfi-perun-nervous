package perun

import (
	"context"
	"fmt"
	"math/big"

	"github.com/nervosnetwork/ckb-sdk-go/v2/collector"
	"github.com/nervosnetwork/ckb-sdk-go/v2/collector/builder"
	"github.com/nervosnetwork/ckb-sdk-go/v2/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/v2/transaction/signer"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"go.uber.org/zap"
)

// MinCellCapacity is the minimum capacity for a secp256k1 cell (61 CKB)
const MinCellCapacity = 6100000000

// TransactionResult contains the result of a submitted transaction
type TransactionResult struct {
	TxHash      string `json:"tx_hash"`
	Status      string `json:"status"`
	BlockNumber uint64 `json:"block_number,omitempty"`
}

// Transfer sends CKB to a recipient address using the CKB SDK
func (c *Client) Transfer(ctx context.Context, toAddress string, amount *big.Int) (string, error) {
	if c.ckbKey == nil {
		return "", fmt.Errorf("private key not loaded")
	}

	// Validate minimum amount
	if amount.Cmp(big.NewInt(MinCellCapacity)) < 0 {
		return "", fmt.Errorf("amount must be at least %d shannons (61 CKB)", MinCellCapacity)
	}

	c.logger.Info("initiating CKB transfer",
		zap.String("from", c.address),
		zap.String("to", toAddress),
		zap.String("amount", amount.String()),
	)

	// Get network type
	network := types.NetworkTest
	if c.config.Network == NetworkMainnet {
		network = types.NetworkMain
	}

	// Create RPC client
	rpcClient, err := rpc.Dial(c.config.RPCURL)
	if err != nil {
		return "", fmt.Errorf("failed to create RPC client: %w", err)
	}

	// Create cell iterator for sender address
	iterator, err := collector.NewLiveCellIteratorFromAddress(rpcClient, c.address)
	if err != nil {
		return "", fmt.Errorf("failed to create cell iterator: %w", err)
	}

	// Build transaction
	txBuilder := builder.NewCkbTransactionBuilder(network, iterator)
	txBuilder.FeeRate = 1000 // 1000 shannons per KB

	// Add output to recipient
	if err := txBuilder.AddOutputByAddress(toAddress, amount.Uint64()); err != nil {
		return "", fmt.Errorf("failed to add output: %w", err)
	}

	// Add change output back to sender
	txBuilder.AddChangeOutputByAddress(c.address)

	// Build the transaction with script groups
	txWithGroups, err := txBuilder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build transaction: %w", err)
	}

	c.logger.Info("transaction built",
		zap.Int("inputs", len(txWithGroups.TxView.Inputs)),
		zap.Int("outputs", len(txWithGroups.TxView.Outputs)),
	)

	// Get private key hex
	privateKeyHex := fmt.Sprintf("0x%x", c.ckbKey.Bytes())

	// Sign transaction
	txSigner := signer.GetTransactionSignerInstance(network)
	_, err = txSigner.SignTransactionByPrivateKeys(txWithGroups, privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	c.logger.Info("transaction signed")

	// Send transaction
	txHash, err := rpcClient.SendTransaction(ctx, txWithGroups.TxView)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	txHashHex := fmt.Sprintf("0x%x", txHash[:])

	c.logger.Info("transaction sent successfully",
		zap.String("tx_hash", txHashHex),
	)

	return txHashHex, nil
}

// GetTransactionStatus gets the status of a transaction
func (c *Client) GetTransactionStatus(ctx context.Context, txHash string) (*TransactionResult, error) {
	rpcClient, err := rpc.Dial(c.config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create RPC client: %w", err)
	}

	// Parse tx hash
	var hash types.Hash
	if len(txHash) >= 2 && txHash[:2] == "0x" {
		txHash = txHash[2:]
	}
	if len(txHash) != 64 {
		return nil, fmt.Errorf("invalid tx hash length")
	}
	for i := 0; i < 32; i++ {
		var b byte
		fmt.Sscanf(txHash[i*2:i*2+2], "%02x", &b)
		hash[i] = b
	}

	// Get transaction
	txWithStatus, err := rpcClient.GetTransaction(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	result := &TransactionResult{
		TxHash: "0x" + txHash,
	}

	if txWithStatus.TxStatus != nil {
		result.Status = string(txWithStatus.TxStatus.Status)
		// BlockNumber is in BlockHash for this SDK version
		if txWithStatus.TxStatus.BlockHash != nil {
			// We can't get block number directly, leave it as 0
			result.BlockNumber = 0
		}
	}

	return result, nil
}
