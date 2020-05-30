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
		_, res := NewPriKey(nil)
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func BenchmarkGenerateKey2(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, res := NewPriKey(nil)
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func TestSign(t *testing.T) {
	const SK = "0x15a8efb503f46667a47aafa8d6f2ac105c72d3af6ff95068c7ec91ab32b00e89"
	priKey, err := NewPriKey(bigFromBase16(SK))
	assert.NoError(t, err)
	// println(sk.ToHex())
	tests := [][3]string{
		{"", "0x1eb14c42f5450b0fad22238b3e2822c701c5f2b81d675f91cbaa635c5e110180", "0x03a919f2f4db5045616849e6dbc01278d0fcb7c7beb79945ad2cddfc75fc0360"},
		{"1234", "0x07e7444d53ee54c2db72e8468cdfd339f4e24bc27906840610bbc13bb99252e8", "0x1bb02fe763067ccedec98721b97196b3e1015fcd5439b1e176ca98aea2e86702"},
		{"The zero address: 0x0000000000000000000000000000000000000000.", "0x270d1100ede3cd8c61c2dda655c9933238d8c895d699577c7d3960f4078ee471", "0x1bd9d5e89f0dac89a66abc1fd3c35a898a5dc1e791bba8e5b57a8f5da8419bd6"},
		{"sunmay -==- laiscome", "0x09a341cfa72a629d5035db84ad125fbb09dbd2a4d1f44cc5aa79268933bc21c2", "0x02c67c1d3338a11251f32c8bec586b1e530b2cb121c257845f2ae50959d7a2fc"},
		{"qushigo!!!!", "0x19ab9c7ac4fe660bc6b5cde7e7cc7c7dd471d7efc441a6e826234f5594b14366", "0x230393b163852416f2c23a36679fdb621f67b91c08b5645ab3187a2afd9c8c38"},
		{"The 4444 address: 0x4444444444444444444444444444444444444444.", "0x05921efd006ffdeea3f39b53ca2b953126652fcda28b6fc4ab979934f7aad72f", "0x082cc2c4b64ac81041efc5e5d01422a476057998f23aa11ff39a6c8838afb6e7"},
	}
	for _, pair := range tests {
		m := []byte(pair[0])
		s := priKey.Sign(m)
		x, y := PointToInt1(s.GetPoint())
		// println(PointToStringG1(s.GetPoint()))
		assert.Equal(t, pair[1][2:], bigToHex32(x), string(m))
		assert.Equal(t, pair[2][2:], bigToHex32(y), string(m))

		// verify signature
		s, err = NewSignature(x, y)
		assert.NoError(t, err)
		assert.True(t, Verify(m, s, priKey.GetPub2()), string(m))
	}
}
