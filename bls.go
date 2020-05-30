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

// private key
type PriKey struct {
	sk big.Int
}

// public key on G1
type PubKey1 struct {
	pk bn256.G1
}

// public key on G2
type PubKey2 struct {
	pk bn256.G2
}

// signature on G1
type Signature struct {
	s bn256.G1
}

// create private key from `k`
// if k is nil, a new random private key will created
func NewPriKey(k *big.Int) (*PriKey, error) {
	var err error
	if k == nil {
		if k, _, err = bn256.RandomG1(rand.Reader); err != nil {
			return nil, err
		}
	}
	sk := &PriKey{sk: *k}
	return sk, nil
}

// return public key on G1
func (k *PriKey) GetPub1() *PubKey1 {
	pk := new(bn256.G1).ScalarBaseMult(&k.sk)
	return &PubKey1{*pk}
}

// return public key on G2
func (k *PriKey) GetPub2() *PubKey2 {
	pk := new(bn256.G2).ScalarBaseMult(&k.sk)
	return &PubKey2{*pk}
}

// Sign signs a message (m) with the private key
//   s = sk * H(m)
// the signature is on G1
func (k *PriKey) Sign(m []byte) *Signature {
	hm := HashToG1(m)
	sig := Signature{}
	sig.s.ScalarMult(hm, &k.sk)
	return &sig
}

func (k *PriKey) ToInt() *big.Int {
	return new(big.Int).Set(&k.sk)
}

func (k *PriKey) ToHex() string {
	return bigToHex32(&k.sk)
}

func (k *PriKey) String() string {
	return k.ToHex()
}

func (p *PubKey1) GetPoint() *bn256.G1 {
	return new(bn256.G1).Set(&p.pk)
}

func (p *PubKey1) Add(other *PubKey1) *PubKey1 {
	return &PubKey1{pk: *new(bn256.G1).Add(&p.pk, &other.pk)}
}

func (p *PubKey2) GetPoint() *bn256.G2 {
	return new(bn256.G2).Set(&p.pk)
}

func (p *PubKey2) Add(other *PubKey2) *PubKey2 {
	return &PubKey2{pk: *new(bn256.G2).Add(&p.pk, &other.pk)}
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
func Verify(m []byte, s *Signature, pk *PubKey2) bool {
	hm := HashToG1(m)
	// hm = -1 * hm
	hm = hm.Neg(hm)
	a := make([]*bn256.G1, 2)
	b := make([]*bn256.G2, 2)
	a[0], b[0] = hm, &pk.pk
	a[1], b[1] = s.GetPoint(), P2
	return bn256.PairingCheck(a, b)
}

func NewSignature(x, y *big.Int) (*Signature, error) {
	s, err := BuildG1(x, y)
	if err != nil {
		return nil, err
	}
	return &Signature{s: *s}, nil
}

func AggregatePubKeys1(keys []PubKey1) *PubKey1 {
	points := make([]*bn256.G1, len(keys))
	for i := 0; i < len(keys); i++ {
		points[i] = &keys[i].pk
	}
	p, _ := aggregatePoints(points).(*bn256.G1)
	return &PubKey1{pk: *p}
}

func AggregatePubKeys2(keys []PubKey2) *PubKey2 {
	points := make([]*bn256.G2, len(keys))
	for i := 0; i < len(keys); i++ {
		points[i] = &keys[i].pk
	}
	p, _ := aggregatePoints(points).(*bn256.G2)
	return &PubKey2{pk: *p}
}

func AggregateSignatures(signs []*Signature) *Signature {
	points := make([]*bn256.G1, len(signs))
	for i := 0; i < len(signs); i++ {
		points[i] = &signs[i].s
	}
	p, _ := aggregatePoints(points).(*bn256.G1)
	return &Signature{s: *p}
}
