package bls

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeccak256(t *testing.T) {
	tests := [][2]string{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"good luck", "63c928ebe044b364ab76033306aaad63642f893b7d796b54d2180f92844d065e"},
	}
	for _, pair := range tests {
		m := []byte(pair[0])
		h := Keccak256(m)
		assert.Equal(t, pair[1], hex.EncodeToString(h), m)
	}
}

