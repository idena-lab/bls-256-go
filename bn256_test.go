package bls

import (
	"testing"
)

func TestHashToG1(t *testing.T) {
	tests := [][3]string{
		{"", "0x07d6361970af1d68e10e2ee74ee851bcd33d23ea24a95f9b474207c128aca6b0", "0x2f71ec16d76213fa8929353cb258bfd10ff486ab60235e4646d0615bb2e3ebd5"},
		{"test", "0x0be7bfb307a4c44d894f21b6ca7e62038d33ca1217976355ebdeaecab65c5c65", "0x0592706fe86d1907e547440f171a8ce75fbe56690e3e5b326a6a04823959bc6c"},
		{"01234567890", "0x0d1d734b265476ca53d0ace6c19e4b517ebf77ed9fdd4fd8e6748825a209d69c", "0x298de683a796279ddd058dd437d5e5f66d057570bd1ff2f81eaa42194140e677"},
		{"abcd-efgh...xyz...ABCD...!", "0x0625543b0c8c7ab770932220485b44abc75d8485ec0d39f8382925d692fa5738", "0x0e4d6a68eda6f9eae1f4ad9119824e5196237f39c024a55e69d8b6a515495c72"},
		{"func TestHashToG1(t *testing.T) { }", "0x0d73cce6478efecab9d9871ed7aa869abeed5514a493d3eb0e746e580eb98d8f", "0x1d2695f881ce4499b2d4e2d181f386b9b6a7ccfcbeaef5583d3bc9c7ba02ac83"},
		{"测试 hashToG1.", "0x2eb70a38c822a2cbd459f712a04935356c6ba63817d9298ed352259c5782b172", "0x248d3971c6ed1286feaeede14861de0a7de52ff3f649c203efec4d8b36f059b8"},
	}
	for _, tt := range tests {
		p := HashToG1([]byte(tt[0]))
		t.Logf(PointToStringG1(p))
		// assert.Equal(t, pair[1], hex.EncodeToString(h), m)
	}
}
