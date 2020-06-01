package bls

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func Test_bigToBytes(t *testing.T) {
	bi := big.NewInt(0x12345678)
	s := BigToBytes(bi, 4)
	assert.Equal(t, hex.EncodeToString(s), "12345678")
}