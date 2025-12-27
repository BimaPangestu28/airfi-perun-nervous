// Package perun provides cell splitting functionality for Perun channel operations.
package perun

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/v2/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"go.uber.org/zap"
)

const (
	// SplitFee is the transaction fee for splitting cells (0.001 CKB)
	SplitFee uint64 = 100000
	// CellMinCapacity is the minimum capacity for a CKB cell (61 CKB) - used locally to avoid collision
	CellMinCapacity uint64 = 6100000000
)

// CellSplitter handles splitting single cells into multiple cells for Perun channel operations.
type CellSplitter struct {
	rpcClient rpc.Client
	logger    *zap.Logger
}

// NewCellSplitter creates a new cell splitter.
func NewCellSplitter(rpcClient rpc.Client, logger *zap.Logger) *CellSplitter {
	return &CellSplitter{
		rpcClient: rpcClient,
		logger:    logger,
	}
}

// CountCells returns the number of cells for a given lock script.
func (cs *CellSplitter) CountCells(ctx context.Context, lockScript *types.Script) (int, error) {
	searchKey := &indexer.SearchKey{
		Script:           lockScript,
		ScriptType:       types.ScriptTypeLock,
		ScriptSearchMode: types.ScriptSearchModeExact,
		WithData:         true,
	}

	cells, err := cs.rpcClient.GetCells(ctx, searchKey, indexer.SearchOrderAsc, 100, "")
	if err != nil {
		return 0, fmt.Errorf("failed to get cells: %w", err)
	}

	// Count only cells without type scripts (pure CKB cells)
	count := 0
	for _, cell := range cells.Objects {
		if cell.Output.Type == nil {
			count++
		}
	}
	return count, nil
}

// GetCells returns all cells for a given lock script.
func (cs *CellSplitter) GetCells(ctx context.Context, lockScript *types.Script) ([]*indexer.LiveCell, error) {
	searchKey := &indexer.SearchKey{
		Script:           lockScript,
		ScriptType:       types.ScriptTypeLock,
		ScriptSearchMode: types.ScriptSearchModeExact,
		WithData:         true,
	}

	cells, err := cs.rpcClient.GetCells(ctx, searchKey, indexer.SearchOrderAsc, 100, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get cells: %w", err)
	}

	// Filter only cells without type scripts (pure CKB cells)
	result := make([]*indexer.LiveCell, 0)
	for _, cell := range cells.Objects {
		if cell.Output.Type == nil {
			result = append(result, cell)
		}
	}
	return result, nil
}

// SplitCell splits a single cell into two cells.
// Returns the transaction hash if successful.
func (cs *CellSplitter) SplitCell(ctx context.Context, privateKey *secp256k1.PrivateKey, lockScript *types.Script) (types.Hash, error) {
	cs.logger.Info("splitting cell for Perun channel preparation")

	// Get all cells
	cells, err := cs.GetCells(ctx, lockScript)
	if err != nil {
		return types.Hash{}, err
	}

	if len(cells) == 0 {
		return types.Hash{}, fmt.Errorf("no cells found")
	}

	if len(cells) >= 2 {
		cs.logger.Info("wallet already has enough cells", zap.Int("count", len(cells)))
		return types.Hash{}, nil // Already has multiple cells
	}

	// Get the single cell
	cell := cells[0]
	totalCapacity := cell.Output.Capacity

	// Calculate split: cell1 gets 61 CKB (for channel token), cell2 gets the rest
	cell1Capacity := CellMinCapacity
	cell2Capacity := totalCapacity - cell1Capacity - SplitFee

	if cell2Capacity < CellMinCapacity {
		return types.Hash{}, fmt.Errorf("insufficient capacity to split: need at least %d shannons, have %d",
			2*CellMinCapacity+SplitFee, totalCapacity)
	}

	cs.logger.Info("splitting cell",
		zap.Uint64("total_capacity", totalCapacity),
		zap.Uint64("cell1_capacity", cell1Capacity),
		zap.Uint64("cell2_capacity", cell2Capacity),
		zap.Uint64("fee", SplitFee),
	)

	// Get secp256k1 cell dep from blockchain
	secp256k1CellDep := getSecp256k1CellDep()

	// Build transaction
	tx := &types.Transaction{
		Version: 0,
		CellDeps: []*types.CellDep{
			secp256k1CellDep,
		},
		Inputs: []*types.CellInput{
			{
				Since:          0,
				PreviousOutput: cell.OutPoint,
			},
		},
		Outputs: []*types.CellOutput{
			{
				Capacity: cell1Capacity,
				Lock:     lockScript,
				Type:     nil,
			},
			{
				Capacity: cell2Capacity,
				Lock:     lockScript,
				Type:     nil,
			},
		},
		OutputsData: [][]byte{{}, {}},
		Witnesses:   [][]byte{make([]byte, 85)}, // Placeholder for signature
	}

	// Sign the transaction
	signedTx, err := cs.signTransaction(tx, privateKey, lockScript)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Submit transaction
	txHash, err := cs.rpcClient.SendTransaction(ctx, signedTx)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	cs.logger.Info("cell split transaction submitted", zap.String("tx_hash", txHash.Hex()))

	// Wait for confirmation
	if err := cs.waitForConfirmation(ctx, *txHash); err != nil {
		return *txHash, fmt.Errorf("transaction not confirmed: %w", err)
	}

	cs.logger.Info("cell split confirmed", zap.String("tx_hash", txHash.Hex()))
	return *txHash, nil
}

// getSecp256k1CellDep returns the cell dep for secp256k1 on testnet.
func getSecp256k1CellDep() *types.CellDep {
	// Testnet secp256k1_blake160_sighash_all cell dep
	txHash := types.HexToHash("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
	return &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: txHash,
			Index:  0,
		},
		DepType: types.DepTypeDepGroup,
	}
}

// signTransaction signs a transaction with the given private key.
func (cs *CellSplitter) signTransaction(tx *types.Transaction, privateKey *secp256k1.PrivateKey, lockScript *types.Script) (*types.Transaction, error) {
	// Create empty witness for placeholder
	witnessArgs := &types.WitnessArgs{
		Lock: make([]byte, 65), // 65 bytes for signature
	}
	witnessBytes := witnessArgs.Serialize()

	// Set witness placeholder before computing hash
	tx.Witnesses[0] = witnessBytes

	// Calculate transaction hash
	txHash := tx.ComputeHash()

	// Calculate message to sign (tx_hash + witness length + witness)
	witnessLen := len(witnessBytes)
	message := make([]byte, 32+8+witnessLen)
	copy(message[:32], txHash[:])
	binary.LittleEndian.PutUint64(message[32:40], uint64(witnessLen))
	copy(message[40:], witnessBytes)

	// Hash the message using blake2b
	messageHash := blake2b.Blake256(message)

	// Sign with secp256k1
	sig := signWithKey(messageHash, privateKey)

	// Update witness with signature
	witnessArgs.Lock = sig
	tx.Witnesses[0] = witnessArgs.Serialize()

	return tx, nil
}

// signWithKey signs a message hash with the private key using recoverable ECDSA.
func signWithKey(messageHash []byte, privateKey *secp256k1.PrivateKey) []byte {
	// Convert secp256k1.PrivateKey to ecdsa.PrivateKey for signing
	ecdsaPrivKey := privateKey.ToECDSA()

	// Sign with recoverable signature
	sig := signRecoverable(ecdsaPrivKey, messageHash)

	return sig
}

// signRecoverable creates a 65-byte recoverable signature [R(32) || S(32) || V(1)].
func signRecoverable(privateKey *ecdsa.PrivateKey, hash []byte) []byte {
	// Use dcrd's secp256k1 for signing
	privKey := secp256k1.PrivKeyFromBytes(privateKey.D.Bytes())

	// Sign the hash
	sig := secp256k1ecdsa.SignCompact(privKey, hash, false)

	// sig is [V(1) || R(32) || S(32)], we need [R(32) || S(32) || V(1)]
	result := make([]byte, 65)
	copy(result[0:32], sig[1:33])   // R
	copy(result[32:64], sig[33:65]) // S
	result[64] = sig[0] - 27        // V (adjust from 27/28 to 0/1)

	return result
}

// waitForConfirmation waits for a transaction to be confirmed.
func (cs *CellSplitter) waitForConfirmation(ctx context.Context, txHash types.Hash) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(2 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for confirmation")
		case <-ticker.C:
			txWithStatus, err := cs.rpcClient.GetTransaction(ctx, txHash)
			if err != nil {
				continue
			}
			if txWithStatus.TxStatus.Status == types.TransactionStatusCommitted {
				return nil
			}
			if txWithStatus.TxStatus.Status == types.TransactionStatusRejected {
				return fmt.Errorf("transaction rejected: %v", txWithStatus.TxStatus.Reason)
			}
		}
	}
}

// EnsureMultipleCells ensures the wallet has at least 2 cells for Perun operations.
func (cs *CellSplitter) EnsureMultipleCells(ctx context.Context, privateKey *secp256k1.PrivateKey, lockScript *types.Script) error {
	count, err := cs.CountCells(ctx, lockScript)
	if err != nil {
		return fmt.Errorf("failed to count cells: %w", err)
	}

	cs.logger.Info("cell count before split", zap.Int("count", count))

	if count >= 2 {
		return nil // Already have enough cells
	}

	if count == 0 {
		return fmt.Errorf("no cells found in wallet")
	}

	// Need to split
	_, err = cs.SplitCell(ctx, privateKey, lockScript)
	if err != nil {
		return fmt.Errorf("failed to split cell: %w", err)
	}

	// Verify split was successful
	newCount, err := cs.CountCells(ctx, lockScript)
	if err != nil {
		return fmt.Errorf("failed to verify cell count after split: %w", err)
	}

	cs.logger.Info("cell count after split", zap.Int("count", newCount))

	if newCount < 2 {
		return fmt.Errorf("cell split did not produce enough cells: got %d", newCount)
	}

	return nil
}
