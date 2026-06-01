package thresholdcore

import (
	"bytes"
	"errors"
	"io"
	"sort"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

const tagParamsID = "thresholdmagic/params_id"

// chilldkg.go ties EncPedPop and CertEq into transport-agnostic step functions
// (no I/O; the Transport-driven session layer lives in the threshold_chilldkg
// package). Scope: fresh key generation only — the refresh path is not wrapped.

// ErrInvalidSessionParams is returned when session parameters are malformed.
var ErrInvalidSessionParams = errors.New("invalid session params")

// ErrDuplicateHostKey is returned when two participants share a host public key
// (host keys must be distinct so an identifier is recoverable from its host key).
var ErrDuplicateHostKey = errors.New("duplicate host public key")

// SessionParams are the parameters all participants must agree on for a session.
// Per ChillDKG there is no random nonce: SessionID is the deterministic params_id
// (see ParamsID), so everyone derives it identically. Per-session freshness comes
// from each participant's fresh ephemeral key, not from SessionID. Construct with
// NewSessionParams; the participant order is derived on demand by IDs().
type SessionParams struct {
	// SessionID is the 32-byte deterministic params_id (see ParamsID).
	SessionID []byte
	// T is the signing threshold (min signers); N is the number of participants.
	T, N uint16
	// HostPubs maps each participant identifier to its long-lived host key.
	HostPubs map[Identifier]*secp.PublicKey
}

// IDs returns all participant identifiers in canonical ascending order
// (Identifier.Less). This is the single source of truth for participant order.
func (p SessionParams) IDs() []Identifier {
	ids := make([]Identifier, 0, len(p.HostPubs))
	for id := range p.HostPubs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Less(ids[j]) })
	return ids
}

// NewSessionParams builds SessionParams from the threshold and the host keys,
// deriving the deterministic SessionID (params_id). It is the recommended way to
// construct a session: every honest party calling it with the same threshold and
// host keys obtains byte-identical parameters.
func NewSessionParams(t uint16, hostPubs map[Identifier]*secp.PublicKey) (SessionParams, error) {
	p := SessionParams{
		T:        t,
		N:        uint16(len(hostPubs)),
		HostPubs: hostPubs,
	}
	if err := p.validateStructure(); err != nil {
		return SessionParams{}, err
	}
	sid, err := ParamsID(p.T, p.HostPubs)
	if err != nil {
		return SessionParams{}, err
	}
	p.SessionID = sid[:]
	return p, nil
}

// ParamsID computes the deterministic session identifier:
//
//	taggedHash("thresholdmagic/params_id",
//	    T(2B) || N(2B) || for each id in ascending order: id.Serialize() || HostPubs[id])
//
// Binding each identifier together with its host key prevents a permutation of
// the participant set from yielding the same id. N is len(hostPubs).
func ParamsID(t uint16, hostPubs map[Identifier]*secp.PublicKey) ([32]byte, error) {
	n := uint16(len(hostPubs))
	ids := SessionParams{HostPubs: hostPubs}.IDs()
	buf := make([]byte, 0, 4+len(ids)*(32+33))
	buf = append(buf, byte(t>>8), byte(t), byte(n>>8), byte(n))
	for _, id := range ids {
		buf = append(buf, id.Serialize()...)
		hp := hostPubs[id]
		buf = append(buf, hp.SerializeCompressed()...)
	}
	return taggedHash(tagParamsID, buf), nil
}

// validateStructure checks the parameters' shape (threshold, counts, identifiers)
// without checking SessionID.
func (p SessionParams) validateStructure() error {
	if p.T < 2 || p.N < 2 || p.T > p.N {
		return ErrInvalidSessionParams
	}
	if len(p.HostPubs) != int(p.N) {
		return ErrInvalidSessionParams
	}
	// Identifiers non-zero; host keys distinct (1:1 map, so RecoverShare can find a
	// participant by its host key).
	seenPub := make(map[string]struct{}, len(p.HostPubs))
	for id, pub := range p.HostPubs {
		if id.S.IsZero() {
			return ErrInvalidZeroScalar
		}
		if pub == nil {
			return ErrMissingHostKey
		}
		k := string(pub.SerializeCompressed())
		if _, dup := seenPub[k]; dup {
			return ErrDuplicateHostKey
		}
		seenPub[k] = struct{}{}
	}
	return nil
}

// Validate checks the session parameters for internal consistency and confirms
// SessionID is the correct deterministic params_id for these parameters.
func (p SessionParams) Validate() error {
	if err := p.validateStructure(); err != nil {
		return err
	}
	want, err := ParamsID(p.T, p.HostPubs)
	if err != nil {
		return err
	}
	if len(p.SessionID) != 32 || !bytes.Equal(p.SessionID, want[:]) {
		return ErrInvalidSessionParams
	}
	return nil
}

// DKGOutput is the per-participant result of a successful session.
type DKGOutput struct {
	Key    KeyPackage
	Public PublicKeyPackage
}

// RecoveryData is the public backup of a completed session: a single shared blob
// (identical for all participants) from which any member recovers its own DKG
// output with its host secret key (see RecoverShare). It holds no secrets — the
// EncShares are additively masked from non-recipients.
type RecoveryData struct {
	Params      SessionParams
	Round1      map[Identifier]Round1Package
	EphPubs     map[Identifier]*secp.PublicKey
	EncShares   map[Identifier]secp.ModNScalar // aggregated enc_secshare per recipient
	Certificate map[Identifier]*schnorr.Signature
}

// ParticipantStep1 runs round 1: it produces the VSS commitment + proof of
// knowledge (via DKGPart1) and a fresh ephemeral key for share encryption.
func ParticipantStep1(
	p SessionParams,
	self Identifier,
	sk SecretKey,
	coeffs []secp.ModNScalar,
	r io.Reader,
) (Round1SecretPackage, Round1Package, EphemeralKey, error) {
	if err := p.Validate(); err != nil {
		return Round1SecretPackage{}, Round1Package{}, EphemeralKey{}, err
	}
	r1s, r1p, err := DKGPart1(self, p.N, p.T, sk, coeffs, r)
	if err != nil {
		return Round1SecretPackage{}, Round1Package{}, EphemeralKey{}, err
	}
	eph, err := NewEphemeralKey(r)
	if err != nil {
		return Round1SecretPackage{}, Round1Package{}, EphemeralKey{}, err
	}
	return r1s, r1p, eph, nil
}

// ParticipantStep2 runs round 2: verify peers' proofs of knowledge and produce
// encrypted (padded) shares for every participant. round1Peers excludes self
// (matching DKGPart2's contract).
func ParticipantStep2(
	p SessionParams,
	r1secret Round1SecretPackage,
	round1Peers map[Identifier]Round1Package,
	eph EphemeralKey,
	hostSk *secp.PrivateKey,
) (Round2SecretPackage, EncRound2, error) {
	return EncPedPopRound2(r1secret, round1Peers, eph, hostSk, p.HostPubs, p.SessionID)
}

// CoordinatorStep1 validates the round-1 broadcast before aggregation: every
// participant must be present with a commitment vector of length T.
func CoordinatorStep1(p SessionParams, round1 map[Identifier]Round1Package) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(round1) != int(p.N) {
		return ErrIncorrectNumberOfPackages
	}
	for _, id := range p.IDs() {
		r1, ok := round1[id]
		if !ok {
			return ErrIncorrectPackage
		}
		if len(r1.Commitment.Coeffs) != int(p.T) {
			return ErrIncorrectNumberOfCommitments
		}
	}
	return nil
}

// CoordinatorFinalize sums the per-recipient ciphertexts across all senders.
func CoordinatorFinalize(perSender map[Identifier]EncRound2, ids []Identifier) (map[Identifier]secp.ModNScalar, error) {
	return AggregateCiphertexts(perSender, ids)
}

// groupCommitment sums every participant's Round1 VSS commitment into the group
// commitment and derives the matching PublicKeyPackage.
func groupCommitment(p SessionParams, round1 map[Identifier]Round1Package) (VerifiableSecretSharingCommitment, PublicKeyPackage, error) {
	ids := p.IDs()
	list := make([]*VerifiableSecretSharingCommitment, 0, len(round1))
	for _, id := range ids {
		r1, ok := round1[id]
		if !ok {
			return VerifiableSecretSharingCommitment{}, PublicKeyPackage{}, ErrIncorrectPackage
		}
		c := r1.Commitment
		list = append(list, &c)
	}
	group, err := sumCommitments(list)
	if err != nil {
		return VerifiableSecretSharingCommitment{}, PublicKeyPackage{}, err
	}
	pkp, err := PKPFromCommitment(ids, group)
	if err != nil {
		return VerifiableSecretSharingCommitment{}, PublicKeyPackage{}, err
	}
	return group, pkp, nil
}

// ParticipantFinalize decrypts and verifies the aggregated share, builds the key
// packages, and signs the transcript (CertEq). round1All is the coordinator's
// broadcast of every Round1 package; the returned signature is sent to all peers,
// and once N are collected callers invoke VerifyCertificate.
func ParticipantFinalize(
	p SessionParams,
	self Identifier,
	encSecshare secp.ModNScalar,
	round1All map[Identifier]Round1Package,
	ephPubs map[Identifier]*secp.PublicKey,
	myHostSk *secp.PrivateKey,
) (DKGOutput, [32]byte, *schnorr.Signature, error) {

	if err := p.Validate(); err != nil {
		return DKGOutput{}, [32]byte{}, nil, err
	}

	group, pkp, err := groupCommitment(p, round1All)
	if err != nil {
		return DKGOutput{}, [32]byte{}, nil, err
	}

	share, err := DecryptAndVerifyShare(self, encSecshare, p.IDs(), ephPubs, myHostSk, p.SessionID, group)
	if err != nil {
		return DKGOutput{}, [32]byte{}, nil, err
	}

	scalar := (secp.ModNScalar)(share)
	verifyingShare := elemBaseMul(&scalar)

	kp := KeyPackage{
		Identifier:     self,
		SecretShare:    share,
		VerifyingShare: verifyingShare,
		VerifyingKey:   pkp.VerifyingKey,
		MinSigners:     p.T,
	}

	eqInput, _, err := BuildEqInput(p, round1All, ephPubs, group, pkp.VerifyingKey)
	if err != nil {
		return DKGOutput{}, [32]byte{}, nil, err
	}
	sig, err := CertEqSign(myHostSk, eqInput)
	if err != nil {
		return DKGOutput{}, [32]byte{}, nil, err
	}

	return DKGOutput{Key: kp, Public: pkp}, eqInput, sig, nil
}

// VerifyCertificate checks the collected signatures form a valid success
// certificate over eqInput and assembles the (self-contained, recoverable)
// RecoveryData. encShares are the aggregated per-recipient encrypted shares.
func VerifyCertificate(
	p SessionParams,
	eqInput [32]byte,
	sigs map[Identifier]*schnorr.Signature,
	round1All map[Identifier]Round1Package,
	ephPubs map[Identifier]*secp.PublicKey,
	encShares map[Identifier]secp.ModNScalar,
) (RecoveryData, error) {

	if err := CertEqVerifyAll(eqInput, sigs, p.HostPubs, int(p.N)); err != nil {
		return RecoveryData{}, err
	}

	return RecoveryData{
		Params:      p,
		Round1:      round1All,
		EphPubs:     ephPubs,
		EncShares:   encShares,
		Certificate: sigs,
	}, nil
}
