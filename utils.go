package bls

import (
	"encoding/hex"
	"math/big"
)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func bigFromBase16(s string) *big.Int {
	if s[:2] == "0x" || s[:2] == "0X" {
		s = s[2:]
	}
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

// convert big int to byte array
// `minLen` is the minimum length of the array
func bigToBytes(bi *big.Int, minLen int) []byte {
	b := bi.Bytes()
	if minLen <= len(b) {
		return b
	}
	m := make([]byte, minLen)
	copy(m[minLen-len(b):], b)
	return m
}

func bigToHex32(bi *big.Int) string {
	return "0x"+hex.EncodeToString(bigToBytes(bi, 32))
}
