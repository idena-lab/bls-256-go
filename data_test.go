package bls

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"testing"
)

type Hash [32]byte

func (h Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

type verifyItem struct {
	// count of keys aggregated
	Keys int `json:"keys"`
	// aggregated G1 public keys
	Apk1 [2]string `json:"apk1"`
	// aggregated G2 public keys
	Apk2 [4]string `json:"apk2"`
	// message to sign
	Message string `json:"message"`
	// aggregated signature
	Signature [2]string `json:"signature"`
}

// generate test cases for verify() in contract
func Test_GenTestsForContractVerify(t *testing.T) {
	tests := []*verifyItem{
		{Keys: 1, Message: ""},
		{Keys: 1, Message: "idena go"},
		{Keys: 1, Message: "long message: 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"},
		{Keys: 2, Message: "2 keys 1"},
		{Keys: 2, Message: "2 keys 2"},
		{Keys: 3, Message: "3 keys"},
		{Keys: 4, Message: "4 keys"},
		{Keys: 10, Message: "10 keys"},
		{Keys: 100, Message: "100 keys"},
		{Keys: 356, Message: "356 keys"},
		{Keys: 800, Message: "800 keys"},
		{Keys: 1024, Message: "1024 keys"},
		{Keys: 2048, Message: "2048 keys"},
		{Keys: 4000, Message: "4000 keys"},
		{Keys: 6000, Message: "4000 keys"},
		{Keys: 9000, Message: "9000 keys"},
		{Keys: 10000, Message: "10000 keys"},
	}
	priKeys := make([]*PriKey, 0)
	pubKeys1 := make([]*PubKey1, 0)
	pubKeys2 := make([]*PubKey2, 0)
	for i, tc := range tests {
		fmt.Printf("generating %v: keys=%v, message=%v\n", i+1, tc.Keys, tc.Message)
		// prepare keys
		for i := len(priKeys); i < tc.Keys; i++ {
			k, _ := NewPriKey(nil)
			priKeys = append(priKeys, k)
			pubKeys1, pubKeys2 = append(pubKeys1, k.GetPub1()), append(pubKeys2, k.GetPub2())
		}
		sigs := make([]*Signature, tc.Keys)
		for i := 0; i < tc.Keys; i++ {
			sigs[i] = priKeys[i].Sign([]byte(tc.Message))
		}
		asig := AggregateSignatures(sigs)
		tc.Signature = asig.ToHex()
		apk1 := AggregatePubKeys1(pubKeys1[:tc.Keys])
		tc.Apk1 = apk1.ToHex()
		apk2 := AggregatePubKeys2(pubKeys2[:tc.Keys])
		tc.Apk2 = apk2.ToHex()
	}
	s, err := json.MarshalIndent(tests, "", "  ")
	assert.NoError(t, err, "json marshal")
	println(string(s))
}

type identity struct {
	pri  *PriKey
	pub1 *PubKey1
	pub2 *PubKey2
}
type identities []*identity

type idState struct {
	Address string    `json:"address"`
	PubKey  [2]string `json:"pubKey"`
}

// attention: this is not the right idena address, just for test
func (id *identity) getAddress() string {
	h := sha256.Sum256(id.pub1.GetPoint().Marshal())
	return "0x" + hex.EncodeToString(h[:20])
}

func (id *identity) toState() *idState {
	return &idState{
		Address: id.getAddress(),
		PubKey:  id.pub1.ToHex(),
	}
}

type idenaCheckState struct {
	Epoch      int      `json:"epoch"`
	Population int      `json:"population"`
	StateRoot  string   `json:"root"`
	FirstId    *idState `json:"firstId"`
	LastId     *idState `json:"lastId"`
	MiddleId   *idState `json:"middleId"`
}

type idenaInitState struct {
	Comment string `json:"comment"`
	Epoch   int    `json:"epoch"`
	// new identities' addresses
	Identities []string `json:"identities"`
	// new identities' public keys (G1)
	PubKeys [][2]string `json:"pubKeys"`
	// check conditions
	Checks idenaCheckState `json:"checks"`
}

type idenaUpdateState struct {
	Comment string `json:"comment"`
	Epoch   int    `json:"epoch"`
	// new identities' addresses
	NewIdentities []string `json:"newIdentities"`
	// new identities' public keys (G1)
	NewPubKeys [][2]string `json:"newPubKeys"`
	// flags of remove identities
	RemoveFlags []byte `json:"removeFlags"`
	RemoveCount int    `json:"removeCount"`
	// flags of signers
	SignFlags []byte `json:"signFlags"`
	// aggregated signature
	Signature [2]string `json:"signature"`
	// aggregated public keys of signers
	Apk2 [4]string `json:"apk2"`
	// check conditions
	Checks *idenaCheckState `json:"checks"`
}

type idenaTestData struct {
	Init    *idenaInitState     `json:"init"`
	Updates []*idenaUpdateState `json:"updates"`
}

func NewIdentity() *identity {
	priKey, _ := NewPriKey(nil)
	return &identity{
		pri:  priKey,
		pub1: priKey.GetPub1(),
		pub2: priKey.GetPub2(),
	}
}

// get all addresses of identities
func (ids identities) getAddresses() []string {
	addresses := make([]string, len(ids))
	for i := 0; i < len(ids); i++ {
		addresses[i] = ids[i].getAddress()
	}
	return addresses
}

// get all public keys on G1 in string
func (ids identities) getPubKeys() [][2]string {
	// this is not the right idena address, just for test
	pubKeys := make([][2]string, len(ids))
	for i := 0; i < len(ids); i++ {
		pubKeys[i] = ids[i].pub1.ToHex()
	}
	return pubKeys
}

type idenaStateManager struct {
	ids   identities
	pool  identities
	root  Hash
	epoch int
}

// add n new identities from pool
// return the slice of the new identities added
func (m *idenaStateManager) addIdentities(n int) identities {
	if len(m.pool) < n {
		for i := 0; i < n; i++ {
			m.pool = append(m.pool, NewIdentity())
		}
	}
	rand.Shuffle(len(m.pool), func(i, j int) {
		m.pool[i], m.pool[j] = m.pool[j], m.pool[i]
	})
	ret := append(identities{}, m.pool[len(m.pool)-n:]...)
	m.pool = m.pool[:len(m.pool)-n]
	m.ids = append(m.ids, ret...)
	return ret
}

// randomly remove n identities in ids
// returns the bit set of the removed indexes
// removed identities will be appended to pool (used to test reused identities)
func (m *idenaStateManager) removeIds(n int) []byte {
	if n < 0 || n > len(m.ids) {
		panic("invalid n to remove")
	}
	flags := make([]byte, (len(m.ids)+7)/8)
	r := rand.Perm(len(m.ids))
	// remove the first n indexes
	for i := 0; i < n; i++ {
		m.pool = append(m.pool, m.ids[r[i]])
		flags[r[i]/8] |= 1 << (r[i] % 8)
	}
	remain := make(identities, 0, len(m.ids)-n)
	for i := n; i < len(m.ids); i++ {
		remain = append(remain, m.ids[r[i]])
	}
	m.ids = remain
	return flags
}

func (m *idenaStateManager) clone() *idenaStateManager {
	cloned := &idenaStateManager{
		ids:   make(identities, len(m.ids)),
		pool:  make(identities, len(m.pool)),
		root:  Hash{},
		epoch: m.epoch,
	}
	copy(cloned.ids, m.ids)
	copy(cloned.pool, m.pool)
	copy(cloned.root[:], m.root[:])
	return cloned
}

func (m *idenaStateManager) reset(o *idenaStateManager) {
	if o == nil {
		return
	}
	m.ids = o.ids
	m.pool = o.pool
	m.root = o.root
	m.epoch = o.epoch
}

func (m *idenaStateManager) quorum() int {
	return len(m.ids)*2/3 + 1
}

// collect signers with the bit set flags
func (m *idenaStateManager) randomSigners(n int) (identities, []byte) {
	if n < 0 {
		panic("at least one singer is required")
	}
	signers := make(identities, n)
	flags := make([]byte, (len(m.ids)+7)/8)
	r := rand.Perm(len(m.ids))
	// make the first n indexes as signer indexes
	for i := 0; i < n; i++ {
		signers[i] = m.ids[r[i]]
		flags[r[i]/8] |= 1 << (r[i] % 8)
	}
	return signers, flags
}

func (m *idenaStateManager) updateRoot(newIds identities, rmFlags []byte) {
	hIds := Hash{}
	for _, id := range newIds {
		addr, _ := hex.DecodeString(id.getAddress()[2:])
		xy := PointToInt1(id.pub1.GetPoint())
		bytes := append(hIds[:], addr...)
		bytes = append(bytes, BigToBytes(xy[0], 32)...)
		bytes = append(bytes, BigToBytes(xy[1], 32)...)
		copy(hIds[:], Keccak256(bytes))
	}
	bytes := append(m.root[:], BigToBytes(big.NewInt(int64(m.epoch)), 16)...)
	bytes = append(bytes, hIds[:]...)
	bytes = append(bytes, Keccak256(rmFlags)...)
	copy(m.root[:], Keccak256(bytes))
}

// sign and aggregate signatures
func (m *idenaStateManager) aggSign(signers identities) (*Signature, *PubKey2) {
	pub2s := make([]*PubKey2, len(signers))
	sigs := make([]*Signature, len(signers))
	for i, id := range signers {
		sigs[i] = id.pri.Sign(m.root[:])
		pub2s[i] = id.pub2
	}
	return AggregateSignatures(sigs), AggregatePubKeys2(pub2s)
}

func (m *idenaStateManager) getCheckState() *idenaCheckState {
	pop := len(m.ids)
	return &idenaCheckState{
		Epoch:      m.epoch,
		Population: pop,
		StateRoot:  "0x" + hex.EncodeToString(m.root[:]),
		FirstId:    m.ids[0].toState(),
		LastId:     m.ids[pop-1].toState(),
		MiddleId:   m.ids[pop/2].toState(),
	}
}

func (m *idenaStateManager) doUpdate(comment string, epoch int, signPercent, addCount, rmCount int) *idenaUpdateState {
	signCount := len(m.ids) * signPercent / 100
	origin := m.clone()
	m.epoch = epoch
	signers, signFlags := m.randomSigners(signCount)
	rmFlags := m.removeIds(rmCount)
	newIds := m.addIdentities(addCount)

	m.updateRoot(newIds, rmFlags)
	signature, apk2 := m.aggSign(signers)

	u := &idenaUpdateState{
		Comment:       comment,
		Epoch:         epoch,
		NewIdentities: newIds.getAddresses(),
		NewPubKeys:    newIds.getPubKeys(),
		RemoveFlags:   rmFlags,
		RemoveCount:   rmCount,
		SignFlags:     signFlags,
		Signature:     signature.ToHex(),
		Apk2:          apk2.ToHex(),
		Checks:        nil,
	}
	isValidUpdate := signCount >= m.quorum()

	if !isValidUpdate {
		m.reset(origin)
	}
	u.Checks = m.getCheckState()
	return u
}

// generate test cases for init() and update() in contract
func Test_GenTestsForContractStates(t *testing.T) {
	m := &idenaStateManager{
		pool: make(identities, 0, 10000),
		ids:  make(identities, 0),
		root: Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}

	initPop := 100
	m.addIdentities(initPop)
	m.updateRoot(m.ids, []byte{})
	// println(m.root.String())

	data := &idenaTestData{}
	data.Init = &idenaInitState{
		Comment:    fmt.Sprintf("init with %v identities", initPop),
		Epoch:      44,
		Identities: m.ids.getAddresses(),
		PubKeys:    m.ids.getPubKeys(),
	}
	data.Updates = make([]*idenaUpdateState, 0)

	data.Updates = append(data.Updates,
		m.doUpdate("update +1 -0", 45, 70, 1, 0),
	)

	println(MustToJson(data, true))
}
