// Package guest provides guest wallet management for AirFi.
package guest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/systemscript"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

// Wallet represents a generated guest wallet for Perun channels.
type Wallet struct {
	ID         string
	PrivateKey *secp256k1.PrivateKey
	Address    string
	LockScript *types.Script
}

// WalletManager manages guest wallets.
type WalletManager struct {
	wallets   map[string]*Wallet
	walletsMu sync.RWMutex
	network   types.Network
}

// NewWalletManager creates a new wallet manager.
func NewWalletManager(network types.Network) *WalletManager {
	return &WalletManager{
		wallets: make(map[string]*Wallet),
		network: network,
	}
}

// GenerateWallet creates a new guest wallet with a random keypair.
func (wm *WalletManager) GenerateWallet() (*Wallet, error) {
	// Generate random 32-byte private key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Create secp256k1 private key
	privKey := secp256k1.PrivKeyFromBytes(keyBytes)

	// Generate wallet ID from first 8 bytes of key hash
	idBytes := blake2b.Blake160(keyBytes)
	walletID := hex.EncodeToString(idBytes[:8])

	// Create wallet
	wallet, err := wm.createWalletFromKey(walletID, privKey)
	if err != nil {
		return nil, err
	}

	// Store wallet
	wm.walletsMu.Lock()
	wm.wallets[walletID] = wallet
	wm.walletsMu.Unlock()

	return wallet, nil
}

// createWalletFromKey creates a wallet from a private key.
func (wm *WalletManager) createWalletFromKey(id string, privKey *secp256k1.PrivateKey) (*Wallet, error) {
	// Get compressed public key
	pubKey := privKey.PubKey().SerializeCompressed()

	// Create lock script using the same method as Perun SDK
	// This ensures address compatibility with Perun's cell iterator
	lockScript, err := systemscript.Secp256K1Blake160SignhashAllByPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create lock script: %w", err)
	}

	// Encode address
	address := encodeAddress(lockScript, wm.network)

	return &Wallet{
		ID:         id,
		PrivateKey: privKey,
		Address:    address,
		LockScript: lockScript,
	}, nil
}

// GetWallet retrieves a wallet by ID.
func (wm *WalletManager) GetWallet(id string) (*Wallet, bool) {
	wm.walletsMu.RLock()
	defer wm.walletsMu.RUnlock()
	wallet, exists := wm.wallets[id]
	return wallet, exists
}

// GetWalletByAddress retrieves a wallet by CKB address.
func (wm *WalletManager) GetWalletByAddress(address string) (*Wallet, bool) {
	wm.walletsMu.RLock()
	defer wm.walletsMu.RUnlock()
	for _, wallet := range wm.wallets {
		if wallet.Address == address {
			return wallet, true
		}
	}
	return nil, false
}

// RemoveWallet removes a wallet from the manager.
func (wm *WalletManager) RemoveWallet(id string) {
	wm.walletsMu.Lock()
	defer wm.walletsMu.Unlock()
	delete(wm.wallets, id)
}

// GetPrivateKeyHex returns the private key as hex string.
func (w *Wallet) GetPrivateKeyHex() string {
	return hex.EncodeToString(w.PrivateKey.Serialize())
}

// DecodeAddress decodes a CKB bech32m address to a lock script.
func DecodeAddress(address string) (*types.Script, error) {
	// Validate address prefix (ckt for testnet, ckb for mainnet)
	if len(address) < 3 {
		return nil, fmt.Errorf("address too short")
	}
	prefix := address[:3]
	if prefix != "ckt" && prefix != "ckb" {
		return nil, fmt.Errorf("invalid address prefix: %s", prefix)
	}

	// Find separator
	sepIdx := -1
	for i := len(address) - 1; i >= 0; i-- {
		if address[i] == '1' {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		return nil, fmt.Errorf("no separator found")
	}

	// Decode data part
	dataStr := address[sepIdx+1:]
	data := make([]int, len(dataStr))
	for i, c := range dataStr {
		idx := -1
		for j, ch := range charset {
			if ch == c {
				idx = j
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid character: %c", c)
		}
		data[i] = idx
	}

	// Remove checksum (last 6)
	if len(data) < 7 {
		return nil, fmt.Errorf("address too short")
	}
	data = data[:len(data)-6]

	// Convert from 5-bit to 8-bit
	converted := convertBitsToBytes(data)
	if len(converted) < 34 { // 1 (format) + 32 (code_hash) + 1 (hash_type)
		return nil, fmt.Errorf("payload too short: %d", len(converted))
	}

	// Parse payload: format_type || code_hash || hash_type || args
	formatType := converted[0]
	if formatType != 0x00 {
		return nil, fmt.Errorf("unsupported format type: %d", formatType)
	}

	codeHash := converted[1:33]
	hashType := converted[33]
	args := converted[34:]

	var ht types.ScriptHashType
	switch hashType {
	case 0x00:
		ht = types.HashTypeData
	case 0x01:
		ht = types.HashTypeType
	case 0x02:
		ht = types.HashTypeData1
	default:
		return nil, fmt.Errorf("unknown hash type: %d", hashType)
	}

	var ch types.Hash
	copy(ch[:], codeHash)

	return &types.Script{
		CodeHash: ch,
		HashType: ht,
		Args:     args,
	}, nil
}

// convertBitsToBytes converts 5-bit groups to bytes.
func convertBitsToBytes(data []int) []byte {
	acc, bits := 0, 0
	result := make([]byte, 0)
	for _, value := range data {
		acc = (acc << 5) | value
		bits += 5
		for bits >= 8 {
			bits -= 8
			result = append(result, byte((acc>>bits)&0xff))
		}
	}
	return result
}

// GetLockScriptHash returns the script hash for a lock script.
func GetLockScriptHash(script *types.Script) types.Hash {
	return script.Hash()
}

// encodeAddress encodes a lock script to CKB bech32m address.
func encodeAddress(script *types.Script, network types.Network) string {
	// Build payload: format_type || code_hash || hash_type || args
	payload := []byte{0x00} // Full address format
	payload = append(payload, script.CodeHash[:]...)
	payload = append(payload, 0x01) // HashTypeType
	payload = append(payload, script.Args...)

	// Convert to 5-bit groups
	converted := convertBits(payload, 8, 5, true)

	// Determine prefix
	hrp := "ckt"
	if network == types.NetworkMain {
		hrp = "ckb"
	}

	return bech32mEncode(hrp, converted)
}

// convertBits converts byte slice between bit sizes.
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
