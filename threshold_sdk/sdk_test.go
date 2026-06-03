package thresholdsdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	params  core.SessionParams
	ids     []core.Identifier
	hostSks map[core.Identifier]*secp.PrivateKey
}

func newFixture(t *testing.T, min, max uint16) fixture {
	t.Helper()
	f := fixture{hostSks: make(map[core.Identifier]*secp.PrivateKey, max)}
	hostPubs := make(map[core.Identifier]*secp.PublicKey, max)
	for i := uint16(1); i <= max; i++ {
		id, err := core.IdentifierFromUint16(i)
		require.NoError(t, err)
		sk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		f.ids = append(f.ids, id)
		f.hostSks[id] = sk
		hostPubs[id] = sk.PubKey()
	}
	params, err := core.NewSessionParams(min, hostPubs)
	require.NoError(t, err)
	f.params = params
	return f
}

type coordResult struct {
	rd  core.RecoveryData
	err error
}

type partResult struct {
	id  core.Identifier
	kp  core.KeyPackage
	err error
}

type ceremony struct {
	f     fixture
	coord *Coordinator
	parts map[core.Identifier]*Participant
	kps   map[core.Identifier]core.KeyPackage
	rd    core.RecoveryData
}

// freshPartStores opens one in-memory Store per participant; the test closes them.
func freshPartStores(t *testing.T, ids []core.Identifier) map[core.Identifier]Store {
	t.Helper()
	ps := make(map[core.Identifier]Store, len(ids))
	for _, id := range ids {
		s, err := OpenBadgerStore("")
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		ps[id] = s
	}
	return ps
}

// newCoordStore opens an in-memory Store for a coordinator (closed by Coordinator.Close).
func newCoordStore(t *testing.T) Store {
	t.Helper()
	s, err := OpenBadgerStore("")
	require.NoError(t, err)
	return s
}

// runDKG drives one ceremony over a real gRPC listener using the given fixture
// and stores, returning the coordinator, participants, their key packages, and
// the recovery blob. Reusable across ceremonies (e.g. same params, shared stores).
func runDKG(t *testing.T, f fixture, coordStore Store, partStores map[core.Identifier]Store) (*Coordinator, map[core.Identifier]*Participant, map[core.Identifier]core.KeyPackage, core.RecoveryData) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	coord, err := NewCoordinator(f.params, "127.0.0.1:0", coordStore)
	require.NoError(t, err)
	t.Cleanup(func() { _ = coord.Close() })
	addr := coord.Addr().String()

	parts := make(map[core.Identifier]*Participant, len(f.ids))
	for _, id := range f.ids {
		p, err := NewParticipant(f.params, f.hostSks[id], addr, partStores[id])
		require.NoError(t, err)
		parts[id] = p
	}

	cc := make(chan coordResult, 1)
	go func() { rd, err := coord.Run(ctx); cc <- coordResult{rd, err} }()

	pc := make(chan partResult, len(f.ids))
	for _, id := range f.ids {
		id, p := id, parts[id]
		go func() { kp, err := p.Run(ctx); pc <- partResult{id, kp, err} }()
	}

	kps := make(map[core.Identifier]core.KeyPackage, len(f.ids))
	for range f.ids {
		r := <-pc
		require.NoErrorf(t, r.err, "participant %v", r.id)
		kps[r.id] = r.kp
	}
	cr := <-cc
	require.NoError(t, cr.err)
	return coord, parts, kps, cr.rd
}

func runCeremony(t *testing.T, min, max uint16) ceremony {
	t.Helper()
	f := newFixture(t, min, max)
	coord, parts, kps, rd := runDKG(t, f, newCoordStore(t), freshPartStores(t, f.ids))
	return ceremony{f: f, coord: coord, parts: parts, kps: kps, rd: rd}
}

func scalarEq(a, b core.SecretShare) bool {
	return (*secp.ModNScalar)(&a).Equals((*secp.ModNScalar)(&b))
}

// vkBytes is the compressed group verifying key — the storage key for a result.
func vkBytes(t *testing.T, kp core.KeyPackage) []byte {
	t.Helper()
	b, err := kp.VerifyingKey.SerializeCompressed()
	require.NoError(t, err)
	return b
}

func TestSDKEndToEnd(t *testing.T) {
	for _, tc := range []struct{ min, max uint16 }{{2, 3}, {3, 5}} {
		tc := tc
		t.Run(fmt.Sprintf("%dof%d", tc.min, tc.max), func(t *testing.T) {
			c := runCeremony(t, tc.min, tc.max)
			f := c.f
			groupKey := vkBytes(t, c.kps[f.ids[0]])

			// Stored under the group verifying key — NOT the (deterministic) session id.
			cblob, err := c.coord.store.GetRecovery(groupKey)
			require.NoError(t, err)
			_, err = c.coord.store.GetRecovery(f.params.SessionID)
			assert.ErrorIs(t, err, ErrNotFound, "must not be keyed by session id")

			ref, err := c.rd.Serialize()
			require.NoError(t, err)
			assert.Equal(t, ref, cblob, "coordinator stored blob differs from returned")
			crd, err := core.ParseRecoveryData(cblob)
			require.NoError(t, err)
			require.NoError(t, crd.Verify())

			for _, id := range f.ids {
				// Every participant stored the identical blob under the same group key.
				pblob, err := c.parts[id].store.GetRecovery(groupKey)
				require.NoError(t, err)
				assert.Equalf(t, ref, pblob, "blob mismatch for %v", id)
				keys, err := c.parts[id].store.List()
				require.NoError(t, err)
				assert.Equalf(t, [][]byte{groupKey}, keys, "store should hold exactly the group key")

				// LoadKeyPackage(groupKey) round-trips and equals the Run output…
				kp, err := c.parts[id].LoadKeyPackage(groupKey)
				require.NoErrorf(t, err, "load %v", id)
				assert.True(t, kp.Identifier.Equal(id), "wrong identifier")
				assert.Equal(t, tc.min, kp.MinSigners)
				assert.True(t, scalarEq(kp.SecretShare, c.kps[id].SecretShare), "load != run")

				// …and an independent RecoverShare from the coordinator's blob.
				out, err := core.RecoverShare(crd, f.hostSks[id])
				require.NoErrorf(t, err, "recover %v", id)
				assert.True(t, scalarEq(kp.SecretShare, out.Key.SecretShare), "load != recover")
			}
		})
	}
}

// TestSDKMultipleKeysPerGroup runs two ceremonies with the SAME participant set
// (same deterministic params_id) sharing each participant's store. They produce
// two distinct keys, both stored and independently loadable — which keying by the
// group verifying key (rather than the session id) is what makes possible.
func TestSDKMultipleKeysPerGroup(t *testing.T) {
	f := newFixture(t, 2, 3)
	partStores := freshPartStores(t, f.ids) // shared across both ceremonies

	_, _, kpsA, _ := runDKG(t, f, newCoordStore(t), partStores)
	_, partsB, kpsB, _ := runDKG(t, f, newCoordStore(t), partStores)

	id0 := f.ids[0]
	require.NotEqual(t, vkBytes(t, kpsA[id0]), vkBytes(t, kpsB[id0]),
		"same params must still yield two distinct keys")

	for _, id := range f.ids {
		keys, err := partStores[id].List()
		require.NoError(t, err)
		assert.Lenf(t, keys, 2, "participant %v should hold two keys", id)

		// Both keys load from the shared store and match their ceremony's share.
		kpA, err := partsB[id].LoadKeyPackage(vkBytes(t, kpsA[id]))
		require.NoError(t, err)
		assert.True(t, scalarEq(kpA.SecretShare, kpsA[id].SecretShare))
		kpB, err := partsB[id].LoadKeyPackage(vkBytes(t, kpsB[id]))
		require.NoError(t, err)
		assert.True(t, scalarEq(kpB.SecretShare, kpsB[id].SecretShare))
	}
}

func TestSDKSelfNotInParams(t *testing.T) {
	f := newFixture(t, 2, 3)
	foreign, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	st, err := OpenBadgerStore("")
	require.NoError(t, err)
	defer st.Close()
	_, err = NewParticipant(f.params, foreign, "127.0.0.1:0", st)
	assert.ErrorIs(t, err, ErrSelfNotInParams)
}

func TestHostKeyFromHex(t *testing.T) {
	sk, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	got, err := HostKeyFromHex(hex.EncodeToString(sk.Serialize()))
	require.NoError(t, err)
	assert.Equal(t, sk.Serialize(), got.Serialize())

	_, err = HostKeyFromHex("abcd") // too short
	assert.Error(t, err)
	_, err = HostKeyFromHex(hex.EncodeToString(make([]byte, 32))) // zero key
	assert.Error(t, err)
}

func TestSDKStalledTimesOut(t *testing.T) {
	f := newFixture(t, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	cstore, err := OpenBadgerStore("")
	require.NoError(t, err)
	coord, err := NewCoordinator(f.params, "127.0.0.1:0", cstore)
	require.NoError(t, err)
	defer coord.Close()
	addr := coord.Addr().String()

	cc := make(chan coordResult, 1)
	go func() { rd, err := coord.Run(ctx); cc <- coordResult{rd, err} }()

	present := f.ids[:len(f.ids)-1] // one participant never shows up
	var stores []Store
	pc := make(chan partResult, len(present))
	for _, id := range present {
		st, err := OpenBadgerStore("")
		require.NoError(t, err)
		stores = append(stores, st)
		p, err := NewParticipant(f.params, f.hostSks[id], addr, st)
		require.NoError(t, err)
		go func() { kp, err := p.Run(ctx); pc <- partResult{id, kp, err} }()
	}
	defer func() {
		for _, s := range stores {
			_ = s.Close()
		}
	}()

	assert.Error(t, (<-cc).err, "coordinator must error when a participant is missing")
	for range present {
		assert.Error(t, (<-pc).err)
	}

	// Nothing was persisted for the aborted ceremony.
	keys, err := cstore.List()
	require.NoError(t, err)
	assert.Empty(t, keys)
}
