package bls

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

func BigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func BigFromBase16(s string) *big.Int {
	if s[:2] == "0x" || s[:2] == "0X" {
		s = s[2:]
	}
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

// convert big int to byte array
// `minLen` is the minimum length of the array
func BigToBytes(bi *big.Int, minLen int) []byte {
	b := bi.Bytes()
	if minLen <= len(b) {
		return b
	}
	m := make([]byte, minLen)
	copy(m[minLen-len(b):], b)
	return m
}

func BigToHex32(bi *big.Int) string {
	return "0x" + hex.EncodeToString(BigToBytes(bi, 32))
}

func MustToJson(v interface{}, pretty ...bool) string {
	var err error
	var s []byte
	if len(pretty) > 0 && pretty[0] {
		s, err = json.MarshalIndent(v, "", "  ")
	} else {
		s, err = json.Marshal(v)
	}
	if err != nil {
		panic(err)
	}
	return string(s)
}
