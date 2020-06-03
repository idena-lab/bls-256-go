package bls

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"math/rand"
	"sort"
	"testing"
)

type Hash [32]byte

func (h Hash) String() string {
	return "0x" + hex.EncodeToString(h[:])
}

type Bytes []byte

func (b Bytes) String() string {
	return "0x" + hex.EncodeToString(b)
}

func (b Bytes) MarshalText() ([]byte, error) {
	return []byte(b.String()), nil
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

		assert.True(t, Verify([]byte(tc.Message), asig, apk2))
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
	Valid      bool     `json:"valid"`
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
	Checks *idenaCheckState `json:"checks"`
}

type idenaUpdateState struct {
	Comment string `json:"comment"`
	Epoch   int    `json:"epoch"`
	// new identities' addresses
	NewIdentities []string `json:"newIdentities"`
	// new identities' public keys (G1)
	NewPubKeys [][2]string `json:"newPubKeys"`
	// flags of remove identities
	RemoveFlags Bytes `json:"removeFlags"`
	RemoveCount int   `json:"removeCount"`
	// flags of signers
	SignFlags Bytes `json:"signFlags"`
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

func NewIdentity(sk *big.Int) *identity {
	priKey, _ := NewPriKey(new(big.Int).Set(sk))
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

// make generated data more similar
var nextPrivateKey = BigFromBase10("666666666666666666666666666666666666666666666666666666666666")

// get n identities from pool
// the removed identities in the pool may be returned
// return the slice of the new identities
func (m *idenaStateManager) getIdsFromPool(n int) identities {
	if len(m.pool) < n {
		for i := 0; i < n; i++ {
			m.pool = append(m.pool, NewIdentity(nextPrivateKey))
			nextPrivateKey = nextPrivateKey.Add(nextPrivateKey, big.NewInt(1))
		}
	}
	// randomly select ids from the pool
	rand.Shuffle(len(m.pool), func(i, j int) {
		m.pool[i], m.pool[j] = m.pool[j], m.pool[i]
	})
	ret := append(identities{}, m.pool[len(m.pool)-n:]...)
	m.pool = m.pool[:len(m.pool)-n]
	return ret
}

// change the set of active identities
// the rmCount identities to remove are selected randomly
// the removed identities will be appended to pool (used to test reused identities)
// returns the bit set of the removed indexes, the slice of new identities added
func (m *idenaStateManager) changeIds(rmCount, addCount int) ([]byte, identities) {
	if rmCount < 0 || rmCount > len(m.ids) {
		panic(fmt.Errorf("try to remove %d from %d ids", rmCount, len(m.ids)))
	}
	newIds := m.getIdsFromPool(addCount)
	// randomly select indexes to remove
	flags := make([]byte, (len(m.ids)+7)/8)
	rmIndexes := rand.Perm(len(m.ids))[:rmCount]
	sort.Ints(rmIndexes)
	// do the remove and add
	// the removed slots be filled by the new id first
	inserted := 0
	empties := make([]int, 0)
	for i := 0; i < rmCount; i++ {
		pos := rmIndexes[i]
		flags[pos/8] |= 1 << (pos % 8)
		m.pool = append(m.pool, m.ids[pos])
		if inserted < len(newIds) {
			m.ids[pos] = newIds[inserted]
			inserted++
		} else {
			empties = append(empties, pos)
		}
	}
	// the remaining new ids will be appended if `addCount > rmCount`
	// the remaining removed slots will be filled by the latter ids from the end if `addCount < rmCount`
	if inserted < len(newIds) {
		m.ids = append(m.ids, newIds[inserted:]...)
	} else {
		moving := len(m.ids) - 1
		for head, tail := 0, len(empties)-1; head <= tail; head++ {
			for ; moving == empties[tail] && moving >= empties[head]; moving-- {
				tail--
			}
			if moving >= empties[head] {
				m.ids[empties[head]] = m.ids[moving]
				moving--
			} else {
				break
			}
		}
		m.ids = m.ids[:moving+1]
	}
	return flags, newIds
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
	return (m.population()*2-1)/3 + 1
}

func (m *idenaStateManager) population() int {
	return len(m.ids)
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
	bytes := append(m.root[:], BigToBytes(big.NewInt(int64(m.epoch)), 32)...)
	bytes = append(bytes, hIds[:]...)
	bytes = append(bytes, Keccak256(rmFlags)...)
	copy(m.root[:], Keccak256(bytes))
}

// sign and aggregate signatures
func (m *idenaStateManager) aggSign(signers identities) (*Signature, *PubKey2) {
	sigs := make([]*Signature, len(signers))
	pub2s := make([]*PubKey2, len(signers))
	for i, id := range signers {
		sigs[i] = id.pri.Sign(m.root[:])
		pub2s[i] = id.pub2
	}
	return AggregateSignatures(sigs), AggregatePubKeys2(pub2s)
}

func (m *idenaStateManager) getCheckState(valid bool) *idenaCheckState {
	pop := len(m.ids)
	return &idenaCheckState{
		Epoch:      m.epoch,
		Valid:      valid,
		Population: pop,
		StateRoot:  "0x" + hex.EncodeToString(m.root[:]),
		FirstId:    m.ids[0].toState(),
		LastId:     m.ids[pop-1].toState(),
		MiddleId:   m.ids[pop/2].toState(),
	}
}

func (m *idenaStateManager) doUpdate(t *testing.T, valid bool, epoch int, enoughSigner bool, rmCount, addCount int) *idenaUpdateState {
	signCount := m.quorum() + rand.Intn(m.population()-m.quorum()) + 1
	if !enoughSigner {
		signCount = rand.Intn(m.quorum()-1) + 1
	}

	origin := m.clone()
	m.epoch = epoch
	signers, signFlags := m.randomSigners(signCount)
	rmFlags, newIds := m.changeIds(rmCount, addCount)

	m.updateRoot(newIds, rmFlags)
	signature, apk2 := m.aggSign(signers)
	// check signature
	assert.True(t, Verify(m.root[:], signature, apk2))
	// check state
	assert.Equal(t, len(origin.ids)-rmCount+addCount, len(m.ids))

	comment := fmt.Sprintf(
		"epoch(%d): %d identities -%d +%d by %d signers(%.2f%%)",
		epoch, len(origin.ids), rmCount, addCount, signCount, float64(signCount)*100/float64(origin.population()),
	)
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

	isValidUpdate := epoch >= origin.epoch && signCount >= origin.quorum()
	assert.Equal(t, valid, isValidUpdate, "validation error for %s", u.Comment)
	if !isValidUpdate {
		m.reset(origin)
	}
	u.Checks = m.getCheckState(isValidUpdate)
	t.Logf("Active identities: %v\n", len(m.ids))
	return u
}

// generate test cases for init() and update() in contract
func Test_GenTestsForContractStates(t *testing.T) {
	initEpoch := 44
	initPop := 100
	m := &idenaStateManager{
		epoch: initEpoch,
		pool:  make(identities, 0, 10000),
		ids:   make(identities, 0),
		root:  Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	m.ids = m.getIdsFromPool(initPop)
	m.updateRoot(m.ids, []byte{})
	// println(m.root.String())

	data := &idenaTestData{}
	data.Init = &idenaInitState{
		Comment:    fmt.Sprintf("epcoch(%d): init with %v identities", m.epoch, m.population()),
		Epoch:      initEpoch,
		Identities: m.ids.getAddresses(),
		PubKeys:    m.ids.getPubKeys(),
		Checks:     m.getCheckState(true),
	}
	data.Updates = make([]*idenaUpdateState, 0)

	// add 1000 identities
	for i := 0; i < 10; i++ {
		data.Updates = append(data.Updates, m.doUpdate(t, true, m.epoch+1, true, 0, 100))
	}

	// case1
	data.Updates = append(data.Updates,
		m.doUpdate(t, true, m.epoch+0, true, 0, 0),
		m.doUpdate(t, true, m.epoch+1, true, 100, 0),
		m.doUpdate(t, true, m.epoch+1, true, 0, 100),
		m.doUpdate(t, true, m.epoch+0, true, 125, 173),
		m.doUpdate(t, true, m.epoch+2, true, 186, 145),
		m.doUpdate(t, true, m.epoch+4, true, 210, 180),
		m.doUpdate(t, true, m.epoch+1, true, 180, 200),
		// invalid cases
		m.doUpdate(t, false, m.epoch+1, false, 100, 120),
		m.doUpdate(t, false, m.epoch-1, true, 100, 120),
		// valid again
		m.doUpdate(t, true, m.epoch+1, true, 80, 110),
	)

	// // case2
	// // add 1000 identities
	// for i := 0; i < 10; i++ {
	// 	data.Updates = append(data.Updates, m.doUpdate(t, true, m.epoch+1, true, 0, 100))
	// }
	// data.Updates = append(data.Updates,
	// 	m.doUpdate(t, true, m.epoch+1, true, 100, 0),
	// 	m.doUpdate(t, true, m.epoch+1, true, 100, 100),
	// 	m.doUpdate(t, true, m.epoch+1, true, 100, 200),
	// 	m.doUpdate(t, true, m.epoch+1, true, 200, 100),
	// 	m.doUpdate(t, true, m.epoch+1, true, 200, 200),
	// 	m.doUpdate(t, true, m.epoch+1, true, 300, 100),
	// 	m.doUpdate(t, true, m.epoch+1, true, 300, 200),
	// 	m.doUpdate(t, true, m.epoch+1, true, 300, 250),
	// 	// out of gas
	// 	// m.doUpdate(t, true, m.epoch+1, true, 100, 300),
	// 	// m.doUpdate(t, true, m.epoch+1, true, 200, 300),
	// 	// m.doUpdate(t, true, m.epoch+1, true, 300, 300),
	// )

	println(MustToJson(data, true))
}
