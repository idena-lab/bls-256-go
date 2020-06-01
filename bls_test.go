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

func TestCheckPubKeyPair(t *testing.T) {
	count := 100
	for i := 0; i < count; i++ {
		priKey, err := NewPriKey(nil)
		assert.NoError(t, err)
		pub1 := priKey.GetPub1()
		pub2 := priKey.GetPub2()
		assert.True(t, CheckPubKeyPair(pub1, pub2), priKey.ToHex())
	}
}

func TestSign(t *testing.T) {
	const SK = "0x15a8efb503f46667a47aafa8d6f2ac105c72d3af6ff95068c7ec91ab32b00e89"
	priKey, err := NewPriKey(BigFromBase16(SK))
	assert.NoError(t, err)
	// println(sk.ToHex())
	tests := [][3]string{
		{"", "0x1eb14c42f5450b0fad22238b3e2822c701c5f2b81d675f91cbaa635c5e110180", "0x03a919f2f4db5045616849e6dbc01278d0fcb7c7beb79945ad2cddfc75fc0360"},
		{"test", "0x21018644bc20df8dc208abc632ba1b5a3d3131b9358bf043303a5f796e9ea42d", "0x0986031ed2cae311f566f4a652a21ab07a450652d8a761296c6dae36649d7eeb"},
		{"address: 0x0000000000000000000000000000000000000000", "0x2c4cec8195f908b892fe0234d4e67c91408d75635bbee7c952f9264d373572b8", "0x02ff60f96d5211b83d94a01e426efaf2b4a5cb91d3cfda82dcec88afc31c6279"},
		{"address: 0x0000000000000000000000000000000000000001", "0x2c18ab45e99cbf21500865b296a1cf5654dfecfc40761a0f7cfce48509e29ac6", "0x1e06068808754a9375a0430621836e42b0546d05831f65bbf1d4e08da1413180"},
		{"address: 0x0000000000000000000000000000000000000002", "0x2dc69a9bc0ed17e2969bf25e2adf12dd19e62c516ab44e745055de98df9acbb0", "0x202c5b593c3c739e225291de6d64cc6de36fdef33b1b9207adb945e2fbf588c8"},
		{"address: 0x0000000000000000000000000000000000000003", "0x27c9686c7e590e681fd141df081a9d5e59bfc4869e74e2f1bcb3076ee3de2356", "0x0488a16d7f38b899f8d561f1ca230ef80183f5d7a9afad64d38e89ae0a1d9a7f"},
		{"address: 0x0000000000000000000000000000000000000004", "0x06aa97ae15fe2aeb23731780ed6871302afe9847ea9dceaf2ed4ac5c88412b8b", "0x01fc0f07def4ed8a8459a58b1e91f5359084b1a3c4821f4e42049189db0fe2f0"},
		{"symbols: ~!@#.$%^&*()_+-=", "0x0a58087c06ba326bfb869f687bdd1d3d7b91777cdd6f1b147510fb12e52ca88a", "0x27a83aa5e87c47474c97a8eb8e83c11eddca6abd4ee5b49b6401f3714296cd6e"},
		{"测试汉字一", "0x0a45e5f6cc4f275305a68d6d467307fff6f625abc4216b12bdcc3ed0145958df", "0x2545f6b7946d0d1d7be7f074e9c661cd767ccc93bc67e19f41abcc38f8f72734"},
		{"测试汉字二", "0x0891f918fbaf068321b01cd34397f45c25d338201110698bfad0cbfa032fe183", "0x2986455d1213eb0449a5dea53b75a299ae2f51ec584097d409b77311817c827a"},
		{"测试汉字三", "0x2e8767c5e1e658742ef644a386f7672fb047a1a2a9f37e355e13937e3745bb14", "0x2954fa186991e386562e425f545838a6ed4aecc4c85ab03aa3ad06084f2c5cb0"},
		{"测试汉字四", "0x142a2caf0f4925dc56550c24c7348969b78a57e79dcdc36cd27a5c5be6f644e5", "0x032f2fe0fa3a463a1e0b231b83ce1a6c59fb071afc0891498bbd94e857266235"},
	}
	badPriKey, _ := NewPriKey(nil)
	for _, pair := range tests {
		m := []byte(pair[0])
		s := priKey.Sign(m)
		ps := PointToInt1(s.GetPoint())
		// println(PointToStringG1(s.GetPoint()))
		assert.Equal(t, pair[1][2:], BigToHex32(ps[0]), string(m))
		assert.Equal(t, pair[2][2:], BigToHex32(ps[1]), string(m))

		// verify signature
		s, err = NewSignature(ps[0], ps[1])
		assert.NoError(t, err)

		// invalid msg
		badM := append(m, "a"...)
		assert.False(t, Verify(badM, s, priKey.GetPub2()), string(m))
		// invalid signature
		badS := priKey.Sign(badM)
		assert.False(t, Verify(m, badS, priKey.GetPub2()), string(m))
		// invalid key
		assert.False(t, Verify(append(m, "a"...), s, badPriKey.GetPub2()), string(m))
		// the right one
		assert.True(t, Verify(m, s, priKey.GetPub2()), string(m))

		// // dump pairing solidity pairing test
		// hm := HashToG1(m)
		// pair := make([]*big.Int, 0)
		// pair = append(pair, PointToInt1(hm)...)
		// pair = append(pair, PointToInt2(priKey.GetPub2().GetPoint())...)
		// pair = append(pair, PointToInt1(s.GetPoint())...)
		// pair = append(pair, PointToInt2(P2)...)
		// // for solidity pairing
		// println(string(m))
		// for _, p := range pair {
		// 	println("0x" + BigToHex32(p))
		// }
	}
}

