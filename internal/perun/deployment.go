package perun

import (
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
	"perun.network/perun-ckb-backend/backend"
)

// Testnet contract deployment transactions:
// Main contracts: https://pudge.explorer.nervos.org/transaction/0xc247df0052ab5d67b6da04bf6f0743696a83db0cf94e2fef192cd29ef4cfe799
// VC contracts: https://pudge.explorer.nervos.org/transaction/0x0f024bbf4180247031d20541eb2757cf15996821d81b9910b5b3e65990502aa2

var (
	// DeploymentTxHash is the transaction hash containing the main Perun contracts
	DeploymentTxHash = types.HexToHash("0xc247df0052ab5d67b6da04bf6f0743696a83db0cf94e2fef192cd29ef4cfe799")

	// VCDeploymentTxHash is the transaction hash containing the virtual channel contracts
	VCDeploymentTxHash = types.HexToHash("0x0f024bbf4180247031d20541eb2757cf15996821d81b9910b5b3e65990502aa2")

	// Contract code hashes (TypeIds from testnet deployment)
	SUDTCodeHash = types.HexToHash("0xd7cb2e882ae04f0ba2d00d46d49ae2a7375f0e0d0a5d0d4aa48cef428d5bc5e5")
	PCTSCodeHash = types.HexToHash("0x96b5e79709e3c4931a35e5af67356e4ab752e5a990fce241fa17c4f6c3d510e2")
	PCLSCodeHash = types.HexToHash("0x4fa6fd8c0ae0e4b870ed748f86cc42afcb47380f51a6864852820c127acb8f83")
	PFLSCodeHash = types.HexToHash("0xa8690a18bde4123fa04e7e5823f0554f196ec0bd04f3bbf8ed4360902fed05a9")
	VCTSCodeHash = types.HexToHash("0x43b3139ed05cdd86d5d0cbbcf414b3d89193a05493593f88e12f4effd1d39fce")
	VCLSCodeHash = types.HexToHash("0x74c694dad6b36e72526a9345153d7f16759b9c3071b7c9119bdc1bb9898f3928")

	// secp256k1_blake160_sighash_all system script on testnet
	DefaultLockCodeHash = types.HexToHash("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8")
	DefaultLockTxHash   = types.HexToHash("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
)

// PFLSMinCapacity is the minimum capacity for the PFLS script
const PFLSMinCapacity = 4100000032

// GetTestnetDeployment returns the Perun contract deployment info for CKB testnet.
func GetTestnetDeployment() backend.Deployment {
	return backend.Deployment{
		Network: types.NetworkTest,

		// PCTS - Perun Channel Type Script (Index 1)
		PCTSDep: types.CellDep{
			OutPoint: &types.OutPoint{
				TxHash: DeploymentTxHash,
				Index:  1,
			},
			DepType: types.DepTypeCode,
		},
		PCTSCodeHash: PCTSCodeHash,
		PCTSHashType: types.HashTypeType,

		// PCLS - Perun Channel Lock Script (Index 2)
		PCLSDep: types.CellDep{
			OutPoint: &types.OutPoint{
				TxHash: DeploymentTxHash,
				Index:  2,
			},
			DepType: types.DepTypeCode,
		},
		PCLSCodeHash: PCLSCodeHash,
		PCLSHashType: types.HashTypeType,

		// PFLS - Perun Funds Lock Script (Index 3)
		PFLSDep: types.CellDep{
			OutPoint: &types.OutPoint{
				TxHash: DeploymentTxHash,
				Index:  3,
			},
			DepType: types.DepTypeCode,
		},
		PFLSCodeHash:    PFLSCodeHash,
		PFLSHashType:    types.HashTypeType,
		PFLSMinCapacity: PFLSMinCapacity,

		// VCTS - Virtual Channel Type Script
		VCTSDep: types.CellDep{
			OutPoint: &types.OutPoint{
				TxHash: VCDeploymentTxHash,
				Index:  0,
			},
			DepType: types.DepTypeCode,
		},
		VCTSCodeHash: VCTSCodeHash,
		VCTSHashType: types.HashTypeType,

		// VCLS - Virtual Channel Lock Script
		VCLSDep: types.CellDep{
			OutPoint: &types.OutPoint{
				TxHash: VCDeploymentTxHash,
				Index:  1,
			},
			DepType: types.DepTypeCode,
		},
		VCLSCodeHash: VCLSCodeHash,
		VCLSHashType: types.HashTypeType,

		// Default lock script (secp256k1_blake160_sighash_all)
		DefaultLockScript: types.Script{
			CodeHash: DefaultLockCodeHash,
			HashType: types.HashTypeType,
			Args:     make([]byte, 20), // Placeholder, will be set per-address
		},
		DefaultLockScriptDep: types.CellDep{
			OutPoint: &types.OutPoint{
				TxHash: DefaultLockTxHash,
				Index:  0,
			},
			DepType: types.DepTypeDepGroup,
		},

		// SUDT mappings (empty for now, using CKBytes only)
		SUDTs:    make(map[types.Hash]types.Script),
		SUDTDeps: make(map[types.Hash]types.CellDep),
	}
}

// TestnetRPCURL is the CKB testnet RPC endpoint.
const TestnetRPCURL = "https://testnet.ckb.dev/rpc"

// TestnetIndexerURL is the CKB testnet indexer endpoint.
const TestnetIndexerURL = "https://testnet.ckb.dev/indexer"

// ChallengeBlocks is the number of blocks for dispute period on testnet.
const ChallengeBlocks = 9
