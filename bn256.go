package bls

import (
	"github.com/idena-lab/bls-256-go/bn256"
	"math/big"
)

// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
var P = BigFromBase10("21888242871839275222246405745257275088696311157297823662689037894645226208583")

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1.
var Order = BigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495617")

var Fp1Div2 = new(big.Int).Div(P, two)
var G1B = big.NewInt(3)

// generator of G1
var P1, _ = BuildG1(big.NewInt(1), big.NewInt(2))

// negative P1
var P1Neg = new(bn256.G1).Neg(P1)

// generator of G2
var P2, _ = BuildG2(
	BigFromBase10("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
	BigFromBase10("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
	BigFromBase10("4082367875863433681332203403145435568316851327593401208105741076214120093531"),
	BigFromBase10("8495653923123431417604973247489272438418190587263600148770280649306958101930"))

// create G1 point from big.Int(s)
func BuildG1(x, y *big.Int) (*bn256.G1, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	xBytes := new(big.Int).Mod(x, P).Bytes()
	yBytes := new(big.Int).Mod(y, P).Bytes()
	m := make([]byte, numBytes*2)
	copy(m[1*numBytes-len(xBytes):], xBytes)
	copy(m[2*numBytes-len(yBytes):], yBytes)
	point := new(bn256.G1)
	if _, err := point.Unmarshal(m); err != nil {
		return nil, err
	}
	return point, nil
}

// create G2 point from big.Int(s)
func BuildG2(xx, xy, yx, yy *big.Int) (*bn256.G2, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	xxBytes := new(big.Int).Mod(xx, P).Bytes()
	xyBytes := new(big.Int).Mod(xy, P).Bytes()
	yxBytes := new(big.Int).Mod(yx, P).Bytes()
	yyBytes := new(big.Int).Mod(yy, P).Bytes()

	m := make([]byte, numBytes*4)
	copy(m[1*numBytes-len(xxBytes):], xxBytes)
	copy(m[2*numBytes-len(xyBytes):], xyBytes)
	copy(m[3*numBytes-len(yxBytes):], yxBytes)
	copy(m[4*numBytes-len(yyBytes):], yyBytes)
	point := new(bn256.G2)
	if _, err := point.Unmarshal(m); err != nil {
		return nil, err
	}
	return point, nil
}

// Try and increment hashing data to a G1 point
func HashToG1(m []byte) *bn256.G1 {
	px := new(big.Int)
	py := new(big.Int)
	h := Keccak256(m)
	bf := append([]byte{0}, h...)
	for {
		h = Keccak256(bf)
		px.SetBytes(h[:32])
		px.Mod(px, P)
		ySqr := g1XToYSquared(px)
		root := calcQuadRes(ySqr, P)
		rootSqr := new(big.Int).Exp(root, two, P)
		if rootSqr.Cmp(ySqr) == 0 {
			py = root
			bf[0] = byte(255)
			signY := Keccak256(bf)[31] % 2
			if signY == 1 {
				py.Sub(P, py)
			}
			break
		}
		bf[0]++
	}
	p, err := BuildG1(px, py)
	if err != nil {
		panic(err)
	}
	return p
}

func g1XToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, P)
	result.Add(result, G1B)
	return result
}

// Currently implementing first method from
// http://mathworld.wolfram.com/QuadraticResidue.html
// Experimentally, this seems to always return the canonical square root,
// however I haven't seen a proof of this.
func calcQuadRes(ySqr *big.Int, q *big.Int) *big.Int {
	resMod4 := new(big.Int).Mod(q, four)
	if resMod4.Cmp(three) == 0 {
		k := new(big.Int).Sub(q, three)
		k.Div(k, four)
		exp := new(big.Int).Add(k, one)
		result := new(big.Int)
		result.Exp(ySqr, exp, q)
		return result
	}
	// TODO: ADD CODE TO CALC QUADRATIC RESIDUE IN OTHER CASES
	return zero
}

func PointToInt1(p *bn256.G1) []*big.Int {
	m := p.Marshal()
	x := new(big.Int).SetBytes(m[0:32])
	y := new(big.Int).SetBytes(m[32:])
	return []*big.Int{x, y}
}

func PointToInt2(p *bn256.G2) []*big.Int {
	m := p.Marshal()
	xx := new(big.Int).SetBytes(m[0:32])
	xy := new(big.Int).SetBytes(m[32:64])
	yx := new(big.Int).SetBytes(m[64:96])
	yy := new(big.Int).SetBytes(m[96:])
	return []*big.Int{xx, xy, yx, yy}
}

func PointToHex1(p *bn256.G1) [2]string {
	xy := PointToInt1(p)
	return [2]string{BigToHex32(xy[0]), BigToHex32(xy[1])}
}

func PointToHex2(p *bn256.G2) [4]string {
	bis := PointToInt2(p)
	return [4]string{BigToHex32(bis[0]), BigToHex32(bis[1]), BigToHex32(bis[2]), BigToHex32(bis[3])}
}

// aggregate points on the curve G1
func aggregatePoints1(points []*bn256.G1) *bn256.G1 {
	if len(points) < 1 {
		return nil
	}
	g := new(bn256.G1).Set(points[0])
	// todo: use go routine
	for i := 1; i < len(points); i++ {
		g = g.Add(g, points[i])
	}
	return g
}

// aggregate points on the curve G2
func aggregatePoints2(points []*bn256.G2) *bn256.G2 {
	if len(points) < 1 {
		return nil
	}
	g := new(bn256.G2).Set(points[0])
	// todo: use go routine
	for i := 1; i < len(points); i++ {
		g = g.Add(g, points[i])
	}
	return g
}
