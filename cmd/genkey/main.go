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
	key, err := secp256k1.RandomNew()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	privateKeyHex := hex.EncodeToString(key.Bytes())
	pubKey := key.PubKey()
	pubKeyHash := blake2b.Blake160(pubKey)

	codeHash := systemscript.GetCodeHash(types.NetworkTest, systemscript.Secp256k1Blake160SighashAll)
	lockScript := &types.Script{
		CodeHash: codeHash,
		HashType: types.HashTypeType,
		Args:     pubKeyHash,
	}

	addr := encodeAddress(lockScript)

	fmt.Println("=== CKB Testnet Wallet ===")
	fmt.Printf("Private Key: 0x%s\n", privateKeyHex)
	fmt.Printf("Address:     %s\n", addr)
	fmt.Println()
	fmt.Println("Get testnet CKB: https://faucet.nervos.org")
}

func encodeAddress(script *types.Script) string {
	payload := []byte{0x00}
	payload = append(payload, script.CodeHash[:]...)
	payload = append(payload, 0x01) // HashTypeType
	payload = append(payload, script.Args...)
	converted, _ := convertBits(payload, 8, 5, true)
	return bech32mEncode("ckt", converted)
}

func convertBits(data []byte, fromBits, toBits int, pad bool) ([]byte, error) {
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
	return result, nil
}

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32mEncode(hrp string, data []byte) string {
	values := make([]int, len(data))
	for i, b := range data {
		values[i] = int(b)
	}
	checksum := createChecksum(hrp, values)
	result := hrp + "1"
	for _, v := range append(values, checksum...) {
		result += string(charset[v])
	}
	return result
}

func createChecksum(hrp string, data []int) []int {
	values := hrpExpand(hrp)
	values = append(values, data...)
	values = append(values, []int{0, 0, 0, 0, 0, 0}...)
	polymod := polymod(values) ^ 0x2bc830a3
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (polymod >> (5 * (5 - i))) & 31
	}
	return checksum
}

func hrpExpand(hrp string) []int {
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

func polymod(values []int) int {
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
