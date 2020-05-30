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

// private key base
type bn256PriKey struct {
	sk big.Int
}

// private key in G1
type PriKey1 struct {
	bn256PriKey
	pk bn256.G1
}

// public key in G1
type PubKey1 struct {
	pk bn256.G1
}

// private key in G2
type PriKey2 struct {
	bn256PriKey
	pk bn256.G2
}

// public key in G2
type PubKey2 struct {
	pk bn256.G2
}

// signature in G1
type Signature struct {
	s bn256.G1
}

// create private key in G1 from `k`
// if k is nil, a new random private key will created
func NewPriKey1(k *big.Int) (*PriKey1, error) {
	var p *bn256.G1
	var err error
	if k == nil {
		if k, p, err = bn256.RandomG1(rand.Reader); err != nil {
			return nil, err
		}
	} else {
		p = new(bn256.G1).ScalarBaseMult(k)
	}
	sk := &PriKey1{bn256PriKey: bn256PriKey{sk: *k}, pk: *p}
	return sk, nil
}

// create private key in G2 from `k`
// if k is nil, a new random private key will created
func NewPriKey2(k *big.Int) (*PriKey2, error) {
	var p *bn256.G2
	var err error
	if k == nil {
		if k, p, err = bn256.RandomG2(rand.Reader); err != nil {
			return nil, err
		}
	} else {
		p = new(bn256.G2).ScalarBaseMult(k)
	}
	sk := &PriKey2{bn256PriKey: bn256PriKey{sk: *k}, pk: *p}
	return sk, nil
}

func (k *PriKey1) GetPub() *PubKey1 {
	return &PubKey1{k.pk}
}

func (k *PriKey2) GetPub() *PubKey2 {
	return &PubKey2{k.pk}
}

// Sign signs a message (m) with the private key
//   s = sk * H(m)
func (k *bn256PriKey) Sign(m []byte) *Signature {
	hm := HashToG1(m)
	sig := Signature{}
	sig.s.ScalarMult(hm, &k.sk)
	return &sig
}

func (k *bn256PriKey) ToInt() *big.Int {
	return new(big.Int).Set(&k.sk)
}

func (k *bn256PriKey) ToHex() string {
	return bigToHex32(&k.sk)
}

func (k *bn256PriKey) String() string {
	return k.ToHex()
}

func (p *PubKey1) GetPoint() *bn256.G1 {
	return new(bn256.G1).Set(&p.pk)
}

func (p *PubKey2) GetPoint() *bn256.G2 {
	return new(bn256.G2).Set(&p.pk)
}

func (s *Signature) GetPoint() *bn256.G1 {
	return new(bn256.G1).Set(&s.s)
}

func Keccak256(m []byte) []byte {
	sha := sha3.NewLegacyKeccak256()
	sha.Write(m)
	return sha.Sum(nil)
}

// Verify checks the signature (s) of a message (m) with the public key (pk)
//   e(H(m), pk) ?== e(s, g2)
func Verify(m []byte, s *Signature, pk *bn256.G2) bool {
	hm := HashToG1(m)
	a := make([]*bn256.G1, 2)
	b := make([]*bn256.G2, 2)
	a[0], b[0] = hm, pk
	a[1], b[1] = s.GetPoint(), P2
	return bn256.PairingCheck(a, b)
}
