//go:build ignore
// +build ignore

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/secp256k1"
	"github.com/nervosnetwork/ckb-sdk-go/v2/systemscript"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

func main() {
	// Generate random key
	key, err := secp256k1.RandomNew()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	// Get private key hex
	privateKeyHex := hex.EncodeToString(key.Bytes())

	// Get public key and compute blake2b hash (first 20 bytes)
	pubKey := key.PubKey()
	pubKeyHash, err := blake2b.Blake160(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to hash public key: %v\n", err)
		os.Exit(1)
	}

	// Create lock script using secp256k1_blake160_sighash_all
	codeHash := systemscript.GetCodeHash(types.NetworkTest, systemscript.Secp256k1Blake160SighashAll)
	lockScript := &types.Script{
		CodeHash: codeHash,
		HashType: types.HashTypeType,
		Args:     pubKeyHash,
	}

	// Generate testnet address (CKB2021 format)
	addr, err := encodeAddress(lockScript, types.NetworkTest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode address: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== CKB Testnet Wallet ===")
	fmt.Println()
	fmt.Printf("Private Key: 0x%s\n", privateKeyHex)
	fmt.Printf("Public Key:  0x%s\n", hex.EncodeToString(pubKey))
	fmt.Printf("PubKey Hash: 0x%s\n", hex.EncodeToString(pubKeyHash))
	fmt.Printf("Address:     %s\n", addr)
	fmt.Println()
	fmt.Println("=== Next Steps ===")
	fmt.Println("1. Save the private key securely")
	fmt.Println("2. Get testnet CKB from faucet: https://faucet.nervos.org")
	fmt.Println("3. Add to config/config.yaml:")
	fmt.Println()
	fmt.Println("ckb:")
	fmt.Println("  network: testnet")
	fmt.Println("  rpc_url: https://testnet.ckb.dev")
	fmt.Printf("  private_key: 0x%s\n", privateKeyHex)
}

// encodeAddress encodes a script to CKB address format
func encodeAddress(script *types.Script, network types.Network) (string, error) {
	// Use bech32m encoding for full address format (CKB2021)
	// Format: hrp + 0x00 + code_hash (32 bytes) + hash_type (1 byte) + args

	payload := make([]byte, 0, 1+32+1+len(script.Args))
	payload = append(payload, 0x00) // Full format indicator
	payload = append(payload, script.CodeHash[:]...)

	var hashTypeByte byte
	switch script.HashType {
	case types.HashTypeType:
		hashTypeByte = 0x01
	case types.HashTypeData:
		hashTypeByte = 0x00
	case types.HashTypeData1:
		hashTypeByte = 0x02
	case types.HashTypeData2:
		hashTypeByte = 0x04
	}
	payload = append(payload, hashTypeByte)
	payload = append(payload, script.Args...)

	// Convert to 5-bit groups for bech32
	converted, err := convertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}

	hrp := "ckt" // testnet
	if network == types.NetworkMain {
		hrp = "ckb"
	}

	return bech32mEncode(hrp, converted)
}

// convertBits converts a byte slice from one bit group to another
func convertBits(data []byte, fromBits, toBits int, pad bool) ([]byte, error) {
	acc := 0
	bits := 0
	result := make([]byte, 0, len(data)*fromBits/toBits+1)
	maxv := (1 << toBits) - 1

	for _, value := range data {
		acc = (acc << fromBits) | int(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			result = append(result, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			result = append(result, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	return result, nil
}

// bech32m character set
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32mEncode encodes data using bech32m
func bech32mEncode(hrp string, data []byte) (string, error) {
	values := make([]int, len(data))
	for i, b := range data {
		values[i] = int(b)
	}
	checksum := bech32mCreateChecksum(hrp, values)
	combined := append(values, checksum...)

	result := hrp + "1"
	for _, v := range combined {
		result += string(charset[v])
	}
	return result, nil
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

func bech32mHrpExpand(hrp string) []int {
	result := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		result = append(result, int(c)>>5)
	}
	result = append(result, 0)
	for _, c := range hrp {
		result = append(result, int(c)&31)
	}
	return result
}

func bech32mCreateChecksum(hrp string, data []int) []int {
	values := append(bech32mHrpExpand(hrp), data...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	polymod := bech32mPolymod(values) ^ 0x2bc830a3 // bech32m constant
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (polymod >> (5 * (5 - i))) & 31
	}
	return checksum
}
