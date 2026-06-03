package thresholdcore

import (
	"crypto/rand"
	"errors"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chillParticipant bundles everything one party holds locally for a ChillDKG run.
type chillParticipant struct {
	id     Identifier
	hostSk *secp.PrivateKey
	hostPk *secp.PublicKey
	secret SecretKey
	coeffs []secp.ModNScalar

	r1secret Round1SecretPackage
	r1pub    Round1Package
	eph      EphemeralKey
	r2secret Round2SecretPackage
	enc      EncRound2
}

// chillResult is the in-process outcome of a happy-path session.
type chillResult struct {
	params    SessionParams
	parts     []chillParticipant
	round1    map[Identifier]Round1Package
	ephPubs   map[Identifier]*secp.PublicKey
	outputs   map[Identifier]DKGOutput
	eqInputs  map[Identifier][32]byte
	sigs      map[Identifier]*schnorr.Signature
	encShare  map[Identifier]secp.ModNScalar
	perSender map[Identifier]EncRound2
}

// newSecrets builds N participants with random host keys, DKG contribution
// secrets, and coefficients. If zeroSum is true the contribution secrets sum to
// 0 mod n (forcing a point-at-infinity group key).
func newParticipants(t *testing.T, min, max uint16, zeroSum bool) []chillParticipant {
	t.Helper()
	ids, err := defaultIdentifiers(max)
	require.NoError(t, err)

	parts := make([]chillParticipant, 0, max)
	var running secp.ModNScalar // sum of secrets so far
	for i := 0; i < int(max); i++ {
		hostSk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)

		var secret secp.ModNScalar
		if zeroSum && i == int(max)-1 {
			// Last secret = -(sum of the others) so the group secret is 0.
			secret.Set(&running)
			secret.Negate()
		} else {
			secret, err = modNRandom()
			require.NoError(t, err)
		}
		running.Add(&secret)

		coeffs, err := generateCoefficients(int(min) - 1)
		require.NoError(t, err)

		parts = append(parts, chillParticipant{
			id:     ids[i],
			hostSk: hostSk,
			hostPk: hostSk.PubKey(),
			secret: SecretKey{Scalar: secret},
			coeffs: coeffs,
		})
	}
	return parts
}

func makeSessionParams(t *testing.T, parts []chillParticipant, min uint16) SessionParams {
	t.Helper()
	hostPubs := make(map[Identifier]*secp.PublicKey, len(parts))
	for i := range parts {
		hostPubs[parts[i].id] = parts[i].hostPk
	}
	params, err := NewSessionParams(min, hostPubs)
	require.NoError(t, err)
	return params
}

// runChillDKG executes a full in-process session (no transport) and returns all
// intermediate artifacts so individual tests can inspect or tamper with them.
func runChillDKG(t *testing.T, min, max uint16, zeroSum bool) (chillResult, error) {
	t.Helper()
	parts := newParticipants(t, min, max, zeroSum)
	params := makeSessionParams(t, parts, min)
	require.NoError(t, params.Validate())

	round1 := make(map[Identifier]Round1Package, max)
	ephPubs := make(map[Identifier]*secp.PublicKey, max)

	// Round 1
	for i := range parts {
		r1s, r1p, eph, err := ParticipantStep1(params, parts[i].id, parts[i].secret, parts[i].coeffs, rand.Reader)
		require.NoError(t, err)
		parts[i].r1secret = r1s
		parts[i].r1pub = r1p
		parts[i].eph = eph
		round1[parts[i].id] = r1p
		ephPubs[parts[i].id] = eph.Pub
	}

	require.NoError(t, CoordinatorStep1(params, round1))

	// Round 2: each participant encrypts shares for all peers.
	perSender := make(map[Identifier]EncRound2, max)
	for i := range parts {
		peers := make(map[Identifier]Round1Package, max-1)
		for id, pkg := range round1 {
			if !id.Equal(parts[i].id) {
				peers[id] = pkg
			}
		}
		r2s, enc, err := ParticipantStep2(params, parts[i].r1secret, peers, parts[i].eph, parts[i].hostSk)
		require.NoError(t, err)
		parts[i].r2secret = r2s
		parts[i].enc = enc
		perSender[parts[i].id] = enc
	}

	// Coordinator aggregation.
	encShare, err := CoordinatorFinalize(perSender, params.IDs())
	require.NoError(t, err)

	// Finalize per participant.
	res := chillResult{
		params:    params,
		parts:     parts,
		round1:    round1,
		ephPubs:   ephPubs,
		outputs:   make(map[Identifier]DKGOutput, max),
		eqInputs:  make(map[Identifier][32]byte, max),
		sigs:      make(map[Identifier]*schnorr.Signature, max),
		encShare:  encShare,
		perSender: perSender,
	}
	for i := range parts {
		out, eqInput, sig, ferr := ParticipantFinalize(params, parts[i].id, encShare[parts[i].id], round1, ephPubs, parts[i].hostSk)
		if ferr != nil {
			return res, ferr
		}
		res.outputs[parts[i].id] = out
		res.eqInputs[parts[i].id] = eqInput
		res.sigs[parts[i].id] = sig
	}
	return res, nil
}

func TestChillDKGEndToEnd(t *testing.T) {
	min, max := uint16(2), uint16(3)

	res, err := runChillDKG(t, min, max, false)
	require.NoError(t, err)

	// All participants agree on the same group verifying key.
	var ref VerifyingKey
	for i, p := range res.parts {
		vk := res.outputs[p.id].Key.VerifyingKey
		if i == 0 {
			ref = vk
			continue
		}
		assert.True(t, ref.E.EquivalentNonConst(&vk.E), "group verifying key agreement")
	}

	// Reconstruction equals the sum of contribution secrets (same invariant as
	// TestDealerDkg) — proves ChillDKG yields the same key as plain PedPop.
	shares := make(map[Identifier]SecretShare, max)
	for _, p := range res.parts {
		shares[p.id] = res.outputs[p.id].Key.SecretShare
	}
	reconstructed, err := Reconstruct(min, shares)
	require.NoError(t, err)

	var expected secp.ModNScalar
	for _, p := range res.parts {
		expected.Add(&p.secret.Scalar)
	}
	assert.True(t, reconstructed.Scalar.Equals(&expected), "reconstructed key matches sum of secrets")

	// CertEq: every participant signed the same eq_input and the certificate verifies.
	ref0 := res.eqInputs[res.parts[0].id]
	for _, p := range res.parts {
		assert.Equal(t, ref0, res.eqInputs[p.id], "all parties signed the same eq_input")
	}
	rec, err := VerifyCertificate(res.params, ref0, res.sigs, res.round1, res.ephPubs, res.encShare)
	require.NoError(t, err)
	assert.Len(t, rec.Certificate, int(max))
	require.NoError(t, rec.Verify())

	// RecoverShare reproduces every participant's KeyPackage from just its host
	// key + the shared blob (the identifier is found by host-key lookup).
	for _, p := range res.parts {
		out, rerr := RecoverShare(rec, p.hostSk)
		require.NoErrorf(t, rerr, "recover %v", p.id)
		assert.Truef(t, out.Key.Identifier.Equal(p.id), "recovered the wrong identifier for %v", p.id)
		want := res.outputs[p.id].Key.SecretShare
		got := out.Key.SecretShare
		assert.Truef(t, (*secp.ModNScalar)(&got).Equals((*secp.ModNScalar)(&want)), "recovered share mismatch for %v", p.id)
		wantVK := res.outputs[p.id].Key.VerifyingKey
		assert.True(t, out.Key.VerifyingKey.E.EquivalentNonConst(&wantVK.E), "recovered VK mismatch")
	}

	// Round-trip: Serialize -> Parse -> Serialize is byte-identical and still recovers.
	blob, err := rec.Serialize()
	require.NoError(t, err)
	rec2, err := ParseRecoveryData(blob)
	require.NoError(t, err)
	blob2, err := rec2.Serialize()
	require.NoError(t, err)
	assert.Equal(t, blob, blob2, "serialization is canonical")
	require.NoError(t, rec2.Verify())
}

func TestChillDKGTamperedCiphertextFails(t *testing.T) {
	min, max := uint16(2), uint16(3)
	parts := newParticipants(t, min, max, false)
	params := makeSessionParams(t, parts, min)

	round1 := make(map[Identifier]Round1Package, max)
	ephPubs := make(map[Identifier]*secp.PublicKey, max)
	for i := range parts {
		r1s, r1p, eph, err := ParticipantStep1(params, parts[i].id, parts[i].secret, parts[i].coeffs, rand.Reader)
		require.NoError(t, err)
		parts[i].r1secret, parts[i].r1pub, parts[i].eph = r1s, r1p, eph
		round1[parts[i].id] = r1p
		ephPubs[parts[i].id] = eph.Pub
	}

	perSender := make(map[Identifier]EncRound2, max)
	for i := range parts {
		peers := make(map[Identifier]Round1Package, max-1)
		for id, pkg := range round1 {
			if !id.Equal(parts[i].id) {
				peers[id] = pkg
			}
		}
		_, enc, err := ParticipantStep2(params, parts[i].r1secret, peers, parts[i].eph, parts[i].hostSk)
		require.NoError(t, err)
		perSender[parts[i].id] = enc
	}

	// Corrupt the ciphertext destined for victim (participant 1); the aggregate
	// check fails regardless of signatures (those are only checked on investigation).
	sender, victim := parts[0].id, parts[1].id
	sh := perSender[sender].Shares[victim]
	one := modNOne()
	sh.Ciphertext.Add(&one)
	perSender[sender].Shares[victim] = sh

	encShare, err := CoordinatorFinalize(perSender, params.IDs())
	require.NoError(t, err)

	_, _, _, err = ParticipantFinalize(params, victim, encShare[victim], round1, ephPubs, parts[1].hostSk)
	assert.ErrorIs(t, err, ErrInvalidSecretShare, "tampered ciphertext must fail the aggregate check")
}

func TestChillDKGCrossSessionReplayFails(t *testing.T) {
	min, max := uint16(2), uint16(3)
	res, err := runChillDKG(t, min, max, false)
	require.NoError(t, err)

	victim := res.parts[1]

	// ChillDKG derives no random session nonce; per-session freshness comes from
	// each participant's fresh ephemeral key, which is bound into every pad. A
	// replayed aggregate ciphertext from another run therefore fails to decrypt
	// because the current session's ephemeral keys differ. Simulate a different
	// session by substituting fresh ephemeral public keys for the senders.
	otherEphPubs := make(map[Identifier]*secp.PublicKey, max)
	for _, p := range res.parts {
		eph, gerr := NewEphemeralKey(rand.Reader)
		require.NoError(t, gerr)
		otherEphPubs[p.id] = eph.Pub
	}

	group, _, err := groupCommitment(res.params, res.round1)
	require.NoError(t, err)
	_, err = DecryptAndVerifyShare(victim.id, res.encShare[victim.id], res.params, otherEphPubs, victim.hostSk, group)
	assert.ErrorIs(t, err, ErrInvalidSecretShare, "ciphertexts bound to other ephemeral keys must not validate")
}

func TestChillDKGInfinityKeyRejected(t *testing.T) {
	min, max := uint16(2), uint16(2)
	_, err := runChillDKG(t, min, max, true)
	assert.ErrorIs(t, err, ErrInfinityVerifyingKey, "zero group secret must be rejected")
}

func TestEcdhPadRoundTrip(t *testing.T) {
	aliceSk, _ := secp.GeneratePrivateKey()
	bobSk, _ := secp.GeneratePrivateKey()
	ephSk, _ := secp.GeneratePrivateKey()
	sessionID := []byte("pad-session-id-padding----------")

	// Alice (ephemeral) -> Bob (host).
	sendPad := ecdhPadSend(ephSk, ephSk.PubKey(), bobSk.PubKey(), sessionID)
	recvPad := ecdhPadRecv(bobSk, ephSk.PubKey(), bobSk.PubKey(), sessionID)
	assert.True(t, sendPad.Equals(&recvPad), "sender and recipient derive the same pad")

	// Changing the session id changes the pad.
	otherPad := ecdhPadRecv(bobSk, ephSk.PubKey(), bobSk.PubKey(), []byte("different-session-padding-------"))
	assert.False(t, recvPad.Equals(&otherPad), "session id is bound into the pad")

	// A different recipient yields a different pad.
	wrongPad := ecdhPadRecv(aliceSk, ephSk.PubKey(), aliceSk.PubKey(), sessionID)
	assert.False(t, recvPad.Equals(&wrongPad), "recipient host key is bound into the pad")
}

func TestEqInputDeterminismAndTamper(t *testing.T) {
	min, max := uint16(2), uint16(3)
	res, err := runChillDKG(t, min, max, false)
	require.NoError(t, err)

	group, pkp, err := groupCommitment(res.params, res.round1)
	require.NoError(t, err)

	a, _, err := BuildEqInput(res.params, res.round1, res.ephPubs, group, pkp.VerifyingKey)
	require.NoError(t, err)
	b, _, err := BuildEqInput(res.params, res.round1, res.ephPubs, group, pkp.VerifyingKey)
	require.NoError(t, err)
	assert.Equal(t, a, b, "eq_input is deterministic")

	// Tamper one participant's commitment -> different eq_input.
	tampered := make(map[Identifier]Round1Package, len(res.round1))
	for id, pkg := range res.round1 {
		tampered[id] = pkg
	}
	victim := res.parts[0].id
	bad := tampered[victim]
	badCoeffs := append([]CoefficientCommitment(nil), bad.Commitment.Coeffs...)
	// Swap in a fresh random point for coeff 0.
	r, _ := modNRandom()
	badCoeffs[0] = elemBaseMul(&r)
	bad.Commitment = VerifiableSecretSharingCommitment{Coeffs: badCoeffs}
	tampered[victim] = bad

	c, _, err := BuildEqInput(res.params, tampered, res.ephPubs, group, pkp.VerifyingKey)
	require.NoError(t, err)
	assert.NotEqual(t, a, c, "tampering the transcript changes eq_input")
}

func TestCertEqRejectsEquivocation(t *testing.T) {
	min, max := uint16(2), uint16(3)
	res, err := runChillDKG(t, min, max, false)
	require.NoError(t, err)

	eqInput := res.eqInputs[res.parts[0].id]

	// Valid certificate accepts.
	require.NoError(t, CertEqVerifyAll(eqInput, res.sigs, res.params.HostPubs, int(max)))

	// One participant signs a different message (equivocation).
	var other [32]byte
	copy(other[:], eqInput[:])
	other[0] ^= 0xff
	badSig, err := CertEqSign(res.parts[1].hostSk, other)
	require.NoError(t, err)

	sigs := make(map[Identifier]*schnorr.Signature, max)
	for id, s := range res.sigs {
		sigs[id] = s
	}
	sigs[res.parts[1].id] = badSig
	assert.ErrorIs(t, CertEqVerifyAll(eqInput, sigs, res.params.HostPubs, int(max)), ErrInvalidCertSignature)
}

// bumpScalar returns s + 1, for corrupting a ciphertext in tests.
func bumpScalar(s secp.ModNScalar) secp.ModNScalar {
	one := modNOne()
	s.Add(&one)
	return s
}

// corruptShare bumps a share's ciphertext but keeps its now-stale signature —
// modelling a coordinator that alters a share it relays (it cannot re-sign).
func corruptShare(sh AuthenticatedShare) AuthenticatedShare {
	return AuthenticatedShare{Ciphertext: bumpScalar(sh.Ciphertext), Sig: sh.Sig}
}

// faultyShare bumps a share's ciphertext and re-signs it with the sender's host
// key — modelling a genuinely Byzantine sender that signs an inconsistent share.
func faultyShare(t *testing.T, sender chillParticipant, recipient Identifier, sessionID []byte, sh AuthenticatedShare) AuthenticatedShare {
	t.Helper()
	ct := bumpScalar(sh.Ciphertext)
	sig, err := SignRound2Share(sender.hostSk, sessionID, sender.id, recipient, sender.eph.Pub, ct)
	require.NoError(t, err)
	return AuthenticatedShare{Ciphertext: ct, Sig: sig}
}

func TestInvestigateBlamesFaultySender(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	ids := res.params.IDs()

	culprit := res.parts[0]
	victim := res.parts[1]

	// A Byzantine sender signs an inconsistent share for the victim.
	res.perSender[culprit.id].Shares[victim.id] = faultyShare(t, culprit, victim.id, res.params.SessionID, res.perSender[culprit.id].Shares[victim.id])

	agg, err := AggregateCiphertexts(res.perSender, ids)
	require.NoError(t, err)
	partials, err := PartialCiphertextsFor(res.perSender, victim.id, ids)
	require.NoError(t, err)

	blame := InvestigateShare(res.params, victim.id, agg[victim.id], partials, res.ephPubs, victim.hostSk, res.round1)
	var fp *FaultyParticipantError
	require.Truef(t, errors.As(blame, &fp), "expected FaultyParticipantError, got %v", blame)
	assert.True(t, fp.Culprit.Equal(culprit.id), "blamed wrong participant")
}

func TestInvestigateBlamesCoordinatorOnShareTamper(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	ids := res.params.IDs()

	sender := res.parts[0]
	victim := res.parts[1]

	// The coordinator alters an honest sender's ciphertext but cannot forge its
	// signature, so the honest sender must NOT be framed — the coordinator is blamed.
	res.perSender[sender.id].Shares[victim.id] = corruptShare(res.perSender[sender.id].Shares[victim.id])

	agg, err := AggregateCiphertexts(res.perSender, ids)
	require.NoError(t, err)
	partials, err := PartialCiphertextsFor(res.perSender, victim.id, ids)
	require.NoError(t, err)

	blame := InvestigateShare(res.params, victim.id, agg[victim.id], partials, res.ephPubs, victim.hostSk, res.round1)
	var fc *FaultyCoordinatorError
	require.Truef(t, errors.As(blame, &fc), "expected FaultyCoordinatorError (honest sender must not be framed), got %v", blame)
}

func TestInvestigateBlamesCoordinatorOnSelfTamper(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	ids := res.params.IDs()
	victim := res.parts[1]

	// Corrupt the victim's own (self) ciphertext: the stale signature won't verify.
	res.perSender[victim.id].Shares[victim.id] = corruptShare(res.perSender[victim.id].Shares[victim.id])

	agg, err := AggregateCiphertexts(res.perSender, ids)
	require.NoError(t, err)
	partials, err := PartialCiphertextsFor(res.perSender, victim.id, ids)
	require.NoError(t, err)

	blame := InvestigateShare(res.params, victim.id, agg[victim.id], partials, res.ephPubs, victim.hostSk, res.round1)
	var fc *FaultyCoordinatorError
	assert.Truef(t, errors.As(blame, &fc), "expected FaultyCoordinatorError, got %v", blame)
}

func TestInvestigateBlamesCoordinatorOnAggregateMismatch(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	ids := res.params.IDs()
	victim := res.parts[1]

	partials, err := PartialCiphertextsFor(res.perSender, victim.id, ids)
	require.NoError(t, err)

	// Authentic parts (valid signatures), but the handed aggregate does not match.
	wrongAgg := bumpScalar(res.encShare[victim.id])

	blame := InvestigateShare(res.params, victim.id, wrongAgg, partials, res.ephPubs, victim.hostSk, res.round1)
	var fc *FaultyCoordinatorError
	assert.Truef(t, errors.As(blame, &fc), "expected FaultyCoordinatorError, got %v", blame)
}

func TestInvestigateInfinityKeyIsNeutral(t *testing.T) {
	res, err := runChillDKG(t, 2, 2, true)
	require.ErrorIs(t, err, ErrInfinityVerifyingKey)
	ids := res.params.IDs()
	victim := res.parts[0]

	partials, err := PartialCiphertextsFor(res.perSender, victim.id, ids)
	require.NoError(t, err)

	blame := InvestigateShare(res.params, victim.id, res.encShare[victim.id], partials, res.ephPubs, victim.hostSk, res.round1)
	assert.ErrorIs(t, blame, ErrInfinityVerifyingKey, "a zero-sum group key must blame no one")
}

func TestInvestigateDeterministicCulprit(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	ids := res.params.IDs()
	victim := res.parts[1]

	// Two Byzantine senders; the lowest-ordered identifier must be blamed.
	res.perSender[res.parts[0].id].Shares[victim.id] = faultyShare(t, res.parts[0], victim.id, res.params.SessionID, res.perSender[res.parts[0].id].Shares[victim.id])
	res.perSender[res.parts[2].id].Shares[victim.id] = faultyShare(t, res.parts[2], victim.id, res.params.SessionID, res.perSender[res.parts[2].id].Shares[victim.id])

	agg, err := AggregateCiphertexts(res.perSender, ids)
	require.NoError(t, err)
	partials, err := PartialCiphertextsFor(res.perSender, victim.id, ids)
	require.NoError(t, err)

	blame := InvestigateShare(res.params, victim.id, agg[victim.id], partials, res.ephPubs, victim.hostSk, res.round1)
	var fp *FaultyParticipantError
	require.True(t, errors.As(blame, &fp))
	want := res.parts[0].id
	if res.parts[2].id.Less(want) {
		want = res.parts[2].id
	}
	assert.True(t, fp.Culprit.Equal(want), "expected the lowest-ordered culprit")
}

func TestPartialCiphertextsFor(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	ids := res.params.IDs()
	victim := res.parts[0].id

	got, err := PartialCiphertextsFor(res.perSender, victim, ids)
	require.NoError(t, err)
	require.Len(t, got, len(ids))
	for _, s := range ids {
		exp := res.perSender[s].Shares[victim]
		g := got[s]
		assert.True(t, g.Ciphertext.Equals(&exp.Ciphertext))
	}

	// Missing sender -> error.
	delete(res.perSender, ids[0])
	_, err = PartialCiphertextsFor(res.perSender, victim, ids)
	assert.ErrorIs(t, err, ErrIncorrectPackage)
}

func TestRandomIdentifier(t *testing.T) {
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		id, err := RandomIdentifier(rand.Reader)
		require.NoError(t, err)
		assert.False(t, id.S.IsZero(), "identifier must be non-zero")
		k := string(id.Serialize())
		assert.Falsef(t, seen[k], "duplicate random identifier")
		seen[k] = true
	}
}

func mustRecoveryData(t *testing.T, res chillResult) RecoveryData {
	t.Helper()
	ref := res.eqInputs[res.parts[0].id]
	rec, err := VerifyCertificate(res.params, ref, res.sigs, res.round1, res.ephPubs, res.encShare)
	require.NoError(t, err)
	return rec
}

func TestRecoverShareTamperedEncShareFails(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	rec := mustRecoveryData(t, res)
	victim := res.parts[1]

	rec.EncShares[victim.id] = bumpScalar(rec.EncShares[victim.id])
	_, err = RecoverShare(rec, victim.hostSk)
	assert.ErrorIs(t, err, ErrInvalidSecretShare, "a tampered share must error, never recover a wrong share")
}

func TestRecoverShareGuards(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	rec := mustRecoveryData(t, res)

	// A host key that belongs to no participant cannot recover anything.
	foreign, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = RecoverShare(rec, foreign)
	assert.ErrorIs(t, err, ErrHostKeyMismatch)

	// A nil host key is rejected.
	_, err = RecoverShare(rec, nil)
	assert.ErrorIs(t, err, ErrHostKeyMismatch)
}

func TestRecoveryDataVerifyRejectsTamperedCert(t *testing.T) {
	res, err := runChillDKG(t, 2, 3, false)
	require.NoError(t, err)
	rec := mustRecoveryData(t, res)
	require.NoError(t, rec.Verify())

	// Replace one signature with a valid sig over a different message (equivocation).
	victim := res.parts[1]
	ref := res.eqInputs[res.parts[0].id]
	var other [32]byte
	copy(other[:], ref[:])
	other[0] ^= 0xff
	badSig, err := CertEqSign(victim.hostSk, other)
	require.NoError(t, err)
	rec.Certificate[victim.id] = badSig
	assert.ErrorIs(t, rec.Verify(), ErrInvalidCertSignature)
}
