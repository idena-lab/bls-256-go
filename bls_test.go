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

func BenchmarkNewPriKey1(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, res := NewPriKey1(nil)
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func BenchmarkGenerateKey2(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, res := NewPriKey2(nil)
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func TestSign(t *testing.T) {
	sk, err := NewPriKey1(bigFromBase16("0x15a8efb503f46667a47aafa8d6f2ac105c72d3af6ff95068c7ec91ab32b00e89"))
	assert.NoError(t, err)
	// println(sk.ToHex())
	tests := [][3]string{
		{"", "0x1eb14c42f5450b0fad22238b3e2822c701c5f2b81d675f91cbaa635c5e110180", "0x03a919f2f4db5045616849e6dbc01278d0fcb7c7beb79945ad2cddfc75fc0360"},
		{"1234", "0x07e7444d53ee54c2db72e8468cdfd339f4e24bc27906840610bbc13bb99252e8", "0x1bb02fe763067ccedec98721b97196b3e1015fcd5439b1e176ca98aea2e86702"},
		{"The zero address: 0x0000000000000000000000000000000000000000.", "0x270d1100ede3cd8c61c2dda655c9933238d8c895d699577c7d3960f4078ee471", "0x1bd9d5e89f0dac89a66abc1fd3c35a898a5dc1e791bba8e5b57a8f5da8419bd6"},
		{"-==-", "0x03480d696bc7e1bd0ccdd30476713b6b22744aebe9b82d4532420ec113e7c0ef", "0x27755a8cc0c360010410740db2db6fcd0a2db728894fe05b84456e359c8aa247"},
		{"!!!!", "0x30484529e6ddb463cd7b777d5a8db319506b238f6319dc4270f023421a76b53a", "0x082515a2624b23f2a4b91e6f807901b7f3a36a469938e54bcb31a1d72428e917"},
		{"The 4444 address: 0x4444444444444444444444444444444444444444.", "0x05921efd006ffdeea3f39b53ca2b953126652fcda28b6fc4ab979934f7aad72f", "0x082cc2c4b64ac81041efc5e5d01422a476057998f23aa11ff39a6c8838afb6e7"},
	}
	for _, pair := range tests {
		m := []byte(pair[0])
		s := sk.Sign(m)
		x, y := PointToInt1(s.GetPoint())
		// println(PointToStringG1(s.GetPoint()))
		assert.Equal(t, pair[1][2:], bigToHex32(x), m)
		assert.Equal(t, pair[2][2:], bigToHex32(y), m)
	}
}
