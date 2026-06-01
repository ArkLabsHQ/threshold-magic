package thresholdcore

import (
	"crypto/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
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
	params   SessionParams
	parts    []chillParticipant
	round1   map[Identifier]Round1Package
	ephPubs  map[Identifier]*secp.PublicKey
	outputs  map[Identifier]DKGOutput
	eqInputs map[Identifier][32]byte
	sigs     map[Identifier]*schnorr.Signature
	encShare map[Identifier]secp.ModNScalar
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
		params:   params,
		parts:    parts,
		round1:   round1,
		ephPubs:  ephPubs,
		outputs:  make(map[Identifier]DKGOutput, max),
		eqInputs: make(map[Identifier][32]byte, max),
		sigs:     make(map[Identifier]*schnorr.Signature, max),
		encShare: encShare,
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
	rec, err := VerifyCertificate(res.params, ref0, res.sigs, res.round1, res.ephPubs)
	require.NoError(t, err)
	assert.Len(t, rec.Certificate, int(max))
	assert.NotEmpty(t, rec.Transcript)
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

	// Sender 0 corrupts the ciphertext destined for victim (participant 1).
	sender, victim := parts[0].id, parts[1].id
	c := perSender[sender].Ciphertexts[victim]
	one := modNOne()
	c.Add(&one)
	perSender[sender].Ciphertexts[victim] = c

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
	_, err = DecryptAndVerifyShare(victim.id, res.encShare[victim.id], res.params.IDs(), otherEphPubs, victim.hostSk, res.params.SessionID, group)
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
