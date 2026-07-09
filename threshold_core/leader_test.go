package thresholdcore

import (
	"bytes"
	"crypto/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// Leader/slave construction: exactly one party (the leader) contributes the secret
// (constant term a0); every other party contributes the identity element. The
// aggregate/threshold pubkey is therefore g^(a0) (post taproot tweak) and is fixed
// by a0 alone — independent of the committee or threshold.
//
// Leadership is NOT part of SessionParams or params_id (those stay byte-identical to
// the BIP spec); it is an SDK-level config passed explicitly as a *Identifier into
// the BIP step functions. nil => classic egalitarian session.

func leaderRandBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func leaderGenKeys(t *testing.T, n int) []*secp.PrivateKey {
	t.Helper()
	ks := make([]*secp.PrivateKey, n)
	for i := range ks {
		k, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		ks[i] = k
	}
	return ks
}

// leaderSessionFor builds a standard (BIP) SessionParams; hostKeys[i] is assigned
// identifier i+1 (so positional order == IDs() order). It returns the params and the
// ordered identifiers, so callers can name the leader.
func leaderSessionFor(t *testing.T, hostKeys []*secp.PrivateKey, threshold uint16) (SessionParams, []Identifier) {
	t.Helper()
	hostPubs := make(map[Identifier]*secp.PublicKey, len(hostKeys))
	ids := make([]Identifier, len(hostKeys))
	for i, hk := range hostKeys {
		var x secp.ModNScalar
		x.SetInt(uint32(i + 1))
		id, err := NewIdentifier(x)
		require.NoError(t, err)
		ids[i] = id
		hostPubs[id] = hk.PubKey()
	}
	p, err := NewSessionParams(threshold, hostPubs)
	require.NoError(t, err)
	return p, ids
}

// runLeaderCeremony drives a full BIP leader/slave ceremony in-process and returns
// each participant's output. hostKeys[leaderIdx] contributes leaderSecret as a0;
// every other party contributes the identity element.
func runLeaderCeremony(t *testing.T, hostKeys []*secp.PrivateKey, leaderIdx int, leaderSecret []byte, threshold uint16) []BIPDKGOutput {
	t.Helper()
	p, ids := leaderSessionFor(t, hostKeys, threshold)
	leader := ids[leaderIdx]
	n := len(hostKeys)

	secretArg := func(i int) []byte {
		if i == leaderIdx {
			return leaderSecret
		}
		return nil
	}

	randoms := make([][]byte, n)
	auxs := make([][]byte, n)
	pmsg1s := make([][]byte, n)
	for i, hk := range hostKeys {
		randoms[i] = leaderRandBytes(t, 32)
		auxs[i] = leaderRandBytes(t, 32)
		m, err := p.BIPParticipantStep1(hk.Serialize(), randoms[i], secretArg(i), &leader)
		require.NoErrorf(t, err, "step1 participant %d", i)
		pmsg1s[i] = m
	}

	cmsg1, err := p.BIPCoordinatorStep1(pmsg1s, &leader)
	require.NoError(t, err, "coordinator_step1")

	pmsg2s := make([][]byte, n)
	for i, hk := range hostKeys {
		m, err := p.BIPParticipantStep2(hk.Serialize(), randoms[i], cmsg1, auxs[i], secretArg(i), &leader)
		require.NoErrorf(t, err, "step2 participant %d", i)
		pmsg2s[i] = m
	}
	cmsg2 := bytes.Join(pmsg2s, nil)

	// Coordinator finalize must also succeed (assembles + verifies the certificate);
	// it operates on the aggregate and needs no role information.
	_, _, err = p.BIPCoordinatorFinalize(cmsg1, pmsg2s)
	require.NoError(t, err, "coordinator_finalize")

	outs := make([]BIPDKGOutput, n)
	for i, hk := range hostKeys {
		out, _, err := p.BIPParticipantFinalize(hk.Serialize(), cmsg1, cmsg2)
		require.NoErrorf(t, err, "finalize participant %d", i)
		outs[i] = out
	}
	return outs
}

// leaderExpectedPubkey computes g^(a0 + tweak), tweak = H_TapTweak(g^a0) — the BIP
// taproot-tweaked group key for a leader whose secret is a0 = leaderSecret.
func leaderExpectedPubkey(t *testing.T, leaderSecret []byte) []byte {
	t.Helper()
	var a0 secp.ModNScalar
	require.False(t, a0.SetByteSlice(leaderSecret), "leader secret out of range")
	com := elemBaseMul(&a0)
	pk, err := encodePointWithInfinity(com)
	require.NoError(t, err)
	th := taggedHash(tagTapTweak, pk)
	tweak := modNFromBytesAllowZero(th[:])
	tweaked := elemAdd(com, elemBaseMul(&tweak))
	out, err := elemSerializeCompressed(tweaked)
	require.NoError(t, err)
	return out
}

// TestLeaderSlavePubkeyStableAcrossMembership is the headline property: the same
// leader secret yields the same group pubkey regardless of the committee size or
// threshold, so a join (or ban) never changes the aggregate key.
func TestLeaderSlavePubkeyStableAcrossMembership(t *testing.T) {
	leaderKey, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	leaderSecret := leaderKey.Serialize() // fixed, membership-independent a0
	want := leaderExpectedPubkey(t, leaderSecret)

	// Committee 1: leader + 2 slaves (n=3, majority t=2).
	keys3 := append([]*secp.PrivateKey{leaderKey}, leaderGenKeys(t, 2)...)
	outs3 := runLeaderCeremony(t, keys3, 0, leaderSecret, 2)
	for i, o := range outs3 {
		require.Equalf(t, want, o.ThresholdPubkey, "committee-3 participant %d pubkey", i)
		require.NotEmpty(t, o.Secshare, "committee-3 participant %d has a share", i)
	}

	// Committee 2: leader + 3 slaves (n=4, majority t=3) — same leader secret.
	keys4 := append([]*secp.PrivateKey{leaderKey}, leaderGenKeys(t, 3)...)
	outs4 := runLeaderCeremony(t, keys4, 0, leaderSecret, 3)
	for i, o := range outs4 {
		require.Equalf(t, want, o.ThresholdPubkey, "committee-4 participant %d pubkey", i)
	}

	// The pubkey is identical across both committees despite different n and t.
	require.Equal(t, outs3[0].ThresholdPubkey, outs4[0].ThresholdPubkey,
		"pubkey must be unchanged across a membership/threshold change")
}

// TestLeaderSlaveRejectsSlaveSecret confirms the coordinator's admission check: a
// slave that contributes a real secret (non-identity commitment) is rejected. The
// session params are the plain BIP params; only the leader argument differs.
func TestLeaderSlaveRejectsSlaveSecret(t *testing.T) {
	leaderKey, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	keys := append([]*secp.PrivateKey{leaderKey}, leaderGenKeys(t, 2)...)

	p, ids := leaderSessionFor(t, keys, 2)
	leader := ids[0]
	// Every party runs as a classic participant (leader == nil), so the slaves
	// produce real, non-identity commitments-to-secret.
	pmsg1s := make([][]byte, len(keys))
	for i, hk := range keys {
		m, err := p.BIPParticipantStep1(hk.Serialize(), leaderRandBytes(t, 32), nil, nil)
		require.NoError(t, err)
		pmsg1s[i] = m
	}
	// Fed into a leader-mode coordinator, the slave positions carry a forbidden secret.
	_, err = p.BIPCoordinatorStep1(pmsg1s, &leader)
	require.ErrorIs(t, err, ErrSlaveNonZeroSecret)
}

// TestIsLeaderID covers the role helper: leadership is a passed-in *Identifier, not a
// session field, and nil means "no leader" (classic).
func TestIsLeaderID(t *testing.T) {
	keys := leaderGenKeys(t, 3)
	_, ids := leaderSessionFor(t, keys, 2)
	leader := ids[0]
	require.True(t, isLeaderID(ids[0], &leader))
	require.False(t, isLeaderID(ids[1], &leader))
	require.False(t, isLeaderID(ids[0], nil)) // classic: no one is the leader
}
