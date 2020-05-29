package bls

import (
	"bls-256-go/bn256"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"math/big"
)

var (
	zero  = big.NewInt(0)
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
)

type PubKey struct {
	Point *bn256.G2
}

type PriKey struct {
	sk *big.Int
	pk *bn256.G1
}

type Signature struct {
	Point *bn256.G1
}

func GenerateKey() *PriKey {
	sk, pk, _ := bn256.RandomG1(rand.Reader)
	return &PriKey{
		sk: sk, pk: pk,
	}
}

// Sign signs a message (m) with the private key
//   s = sk * H(m)
func (k *PriKey) Sign(m []byte) *Signature {
	hm := HashToG1(m)
	sig := Signature{}
	sig.Point.ScalarMult(hm, k.sk)
	return &sig
}

func Keccak256(m []byte) []byte {
	sha := sha3.NewLegacyKeccak256()
	sha.Write(m)
	return sha.Sum(nil)
}

// Verify checks the signature (s) of a message (m) with the public key (pk)
//   e(H(m), pk) ?== e(s, g2)
func Verify(m []byte, s *Signature, pk *PubKey) bool {
	hm := HashToG1(m)
	a := make([]*bn256.G1, 2)
	b := make([]*bn256.G2, 2)
	a[0], b[0] = hm, pk.Point
	a[1], b[1] = s.Point, P2
	return bn256.PairingCheck(a, b)
}
