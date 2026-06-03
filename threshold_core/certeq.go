package thresholdcore

import (
	"errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// CertEq is the certifying equality check from ChillDKG: each participant
// BIP340-signs the transcript hash (eq_input) under its host key, and collecting
// N valid signatures on the same eq_input proves every honest party computed the
// identical transcript, defeating an equivocating coordinator.

const tagCertEq = "thresholdmagic/certeq"

// ErrInvalidCertSignature is returned when a certificate signature fails to verify.
var ErrInvalidCertSignature = errors.New("invalid certeq signature")

// serializeTranscript builds the canonical, fully deterministic byte string that
// CertEq signs over (its tagged hash is eq_input). It must be byte-identical for
// every honest party, so it avoids JSON (Go map order is nondeterministic);
// participants are emitted in ascending Identifier order, every point is SEC1
// compressed (33 bytes) and every scalar is 32-byte big-endian.
//
// Byte layout (|| = concatenation; n = participants, t = threshold; all fixed-width):
//
//	SessionID                  32 bytes (deterministic params_id)
//	T                          2 bytes, uint16 big-endian
//	N                          2 bytes, uint16 big-endian
//	for each id (asc):         id.Serialize() (32) || HostPubs[id] (33)
//	for each id (asc):         Commitment.Coeffs[0..t-1] (t×33) ||
//	                           ProofOfKnowledge.R (33) || .Z (32) || ephPubs[id] (33)
//	group.Coeffs[0..t-1]       t × 33 bytes (summed VSS commitment)
//	vk.E                       33 bytes (group verifying key)
//
// eq_input = taggedHash("thresholdmagic/certeq", <the bytes above>).
func serializeTranscript(
	p SessionParams,
	round1 map[Identifier]Round1Package,
	ephPubs map[Identifier]*secp.PublicKey,
	group VerifiableSecretSharingCommitment,
	vk VerifyingKey,
) ([]byte, error) {

	ids := p.IDs()

	var buf []byte
	buf = append(buf, p.SessionID...)
	buf = append(buf, byte(p.T>>8), byte(p.T), byte(p.N>>8), byte(p.N))

	for _, id := range ids {
		buf = append(buf, id.Serialize()...)
		hp, ok := p.HostPubs[id]
		if !ok {
			return nil, ErrMissingHostKey
		}
		buf = append(buf, hp.SerializeCompressed()...)
	}

	for _, id := range ids {
		r1, ok := round1[id]
		if !ok {
			return nil, ErrIncorrectPackage
		}
		for _, c := range r1.Commitment.Coeffs {
			cb, err := elemSerializeCompressed(c)
			if err != nil {
				return nil, err
			}
			buf = append(buf, cb...)
		}
		rb, err := elemSerializeCompressed(r1.ProofOfKnowledge.R)
		if err != nil {
			return nil, err
		}
		buf = append(buf, rb...)
		zb := r1.ProofOfKnowledge.Z.Bytes()
		buf = append(buf, zb[:]...)

		ep, ok := ephPubs[id]
		if !ok {
			return nil, ErrMissingEphKey
		}
		buf = append(buf, ep.SerializeCompressed()...)
	}

	for _, c := range group.Coeffs {
		cb, err := elemSerializeCompressed(c)
		if err != nil {
			return nil, err
		}
		buf = append(buf, cb...)
	}
	vkb, err := elemSerializeCompressed(vk.E)
	if err != nil {
		return nil, err
	}
	buf = append(buf, vkb...)

	return buf, nil
}

// BuildEqInput returns the 32-byte transcript hash every participant signs
// (eq_input) along with the raw transcript bytes (stored in RecoveryData). The
// exact, canonical byte layout is specified on serializeTranscript.
func BuildEqInput(
	p SessionParams,
	round1 map[Identifier]Round1Package,
	ephPubs map[Identifier]*secp.PublicKey,
	group VerifiableSecretSharingCommitment,
	vk VerifyingKey,
) ([32]byte, []byte, error) {
	transcript, err := serializeTranscript(p, round1, ephPubs, group, vk)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return taggedHash(tagCertEq, transcript), transcript, nil
}

// CertEqSign produces a BIP340 signature on eqInput under the host key.
func CertEqSign(hostSk *secp.PrivateKey, eqInput [32]byte) (*schnorr.Signature, error) {
	return schnorr.Sign(hostSk, eqInput[:])
}

// CertEqVerifyAll checks that sigs contains exactly n valid signatures on
// eqInput, one per host key. Any missing, extra, or invalid signature is a failure.
func CertEqVerifyAll(
	eqInput [32]byte,
	sigs map[Identifier]*schnorr.Signature,
	hostPubs map[Identifier]*secp.PublicKey,
	n int,
) error {
	if len(sigs) != n {
		return ErrIncorrectNumberOfPackages
	}
	for id, sig := range sigs {
		pub, ok := hostPubs[id]
		if !ok {
			return ErrUnknownIdentifier
		}
		if sig == nil || !sig.Verify(eqInput[:], pub) {
			return ErrInvalidCertSignature
		}
	}
	return nil
}
