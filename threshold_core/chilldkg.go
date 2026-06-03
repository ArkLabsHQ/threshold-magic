package thresholdcore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	return EncPedPopRound2(r1secret, round1Peers, eph, hostSk, p)
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

	share, err := DecryptAndVerifyShare(self, encSecshare, p, ephPubs, myHostSk, group)
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

// BIP-exact ChillDKG (bip-frost-dkg): the spec-compliant path, reproducing the BIP
// wire/hashing byte-for-byte (validated against the upstream vectors) on this
// package's objects. Hybrid AuthenticatedShare sigs ride alongside, not in the wire.

// orderedHostPubs returns the compressed host pubkeys in participant order (IDs()).
func (p SessionParams) orderedHostPubs() [][]byte {
	ids := p.IDs()
	pubs := make([][]byte, len(ids))
	for i, id := range ids {
		pubs[i] = p.HostPubs[id].SerializeCompressed()
	}
	return pubs
}

// BIPParamsID is the BIP params_id: tagged_hash("BIP DKG/params_id", t(4B BE) ‖
// ∥hostpubkeys). Positional (no identifiers); accepts any t in 1..n.
func BIPParamsID(t uint32, hostpubkeys [][]byte) [32]byte {
	parts := make([][]byte, 0, 1+len(hostpubkeys))
	parts = append(parts, be32(t))
	parts = append(parts, hostpubkeys...)
	return bipHash("params_id", parts...)
}

// BIPHostpubkeyGen is chilldkg.hostpubkey_gen: the 33-byte compressed key for hostseckey.
func BIPHostpubkeyGen(hostseckey []byte) ([]byte, error) {
	if len(hostseckey) != 32 {
		return nil, ErrSeckeyLen
	}
	var d secp.ModNScalar
	if d.SetByteSlice(hostseckey) || d.IsZero() {
		return nil, ErrSeckeyRange
	}
	return elemSerializeCompressed(elemBaseMul(&d))
}

// bipVSSGenerate is VSS.generate: coeffs[i] = tagged_hash("vss coeffs", seed ‖ i).
func bipVSSGenerate(seed []byte, t uint32) []secp.ModNScalar {
	coeffs := make([]secp.ModNScalar, t)
	for i := uint32(0); i < t; i++ {
		ch := bipHash("vss coeffs", seed, be32(i))
		coeffs[i] = modNFromBytesAllowZero(ch[:])
	}
	return coeffs
}

// bipVSSSecshares is VSS.secshares(n) = [f(1), ..., f(n)], via evaluatePolynomial.
func bipVSSSecshares(coeffs []secp.ModNScalar, n int) ([]secp.ModNScalar, error) {
	out := make([]secp.ModNScalar, n)
	for i := 0; i < n; i++ {
		var x secp.ModNScalar
		x.SetInt(uint32(i + 1))
		id, err := NewIdentifier(x)
		if err != nil {
			return nil, err
		}
		out[i] = evaluatePolynomial(id, coeffs)
	}
	return out, nil
}

// BIPParticipantStep1 is chilldkg.participant_step1: the deterministic EncPedPop
// round-1 message com(33·t) ‖ pop(64) ‖ pubnonce(33) ‖ enc_shares(32·n).
func (p SessionParams) BIPParticipantStep1(hostSk *secp.PrivateKey, random []byte) ([]byte, error) {
	if len(random) != 32 {
		return nil, ErrInvalidSessionParams
	}
	hostseckey := hostSk.Serialize()
	hostpubkeys := p.orderedHostPubs()
	t := uint32(p.T)
	n := len(hostpubkeys)

	hpk := hostSk.PubKey().SerializeCompressed()
	idx := -1
	for i, k := range hostpubkeys {
		if bytes.Equal(k, hpk) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNotInParams
	}

	// Deterministic key generation (encpedpop.participant_step1).
	encCtx := encContextBytes(t, hostpubkeys)
	simplSeed := bipHash("encpedpop seed", hostseckey, random, encCtx)
	simplAux := bipHash("simplpedpop aux", simplSeed[:])
	secnonceH := bipHash("encpedpop secnonce", simplSeed[:])
	secnonceScalar := modNFromBytesAllowZero(secnonceH[:])
	secnoncePriv := secp.NewPrivateKey(&secnonceScalar)
	pubnoncePub := secnoncePriv.PubKey()
	pubnonce := pubnoncePub.SerializeCompressed()

	// SimplPedPop: derive coeffs from the seed, then commit + share.
	coeffs := bipVSSGenerate(simplSeed[:], t)
	_, commitPts, err := generateSecretPolynomial(&coeffs[0], uint16(n), uint16(t), coeffs[1:])
	if err != nil {
		return nil, err
	}
	com, err := VerifiableSecretSharingCommitment{Coeffs: commitPts}.SerializeCompressed()
	if err != nil {
		return nil, err
	}
	shares, err := bipVSSSecshares(coeffs, n)
	if err != nil {
		return nil, err
	}

	// Proof-of-possession over idx, signed with the VSS secret a0.
	a0 := coeffs[0].Bytes()
	pop, err := bipSchnorrSign(be32(uint32(idx)), a0[:], simplAux[:], bipTag+"pop message")
	if err != nil {
		return nil, err
	}

	// EncPedPop encrypt the shares (deckey = host secret).
	cts, err := bipEncryptMulti(secnoncePriv, hostSk, pubnoncePub, hostpubkeys, encCtx, idx, shares)
	if err != nil {
		return nil, err
	}

	// pmsg1 = simpl_pmsg ‖ pubnonce ‖ enc_shares, simpl_pmsg = com ‖ pop.
	pmsg := make([]byte, 0, len(com)+64+33+32*n)
	pmsg = append(pmsg, com...)
	pmsg = append(pmsg, pop...)
	pmsg = append(pmsg, pubnonce...)
	for i := range cts {
		b := cts[i].Bytes()
		pmsg = append(pmsg, b[:]...)
	}
	return pmsg, nil
}

// parseBIPPmsg1 splits a round-1 message: com(33·t) ‖ pop(64) ‖ pubnonce(33) ‖ enc_shares(32·n).
func parseBIPPmsg1(b []byte, t, n int) (com VerifiableSecretSharingCommitment, pop, pubnonce []byte, encShares []secp.ModNScalar, err error) {
	if len(b) != 33*t+64+33+32*n {
		return VerifiableSecretSharingCommitment{}, nil, nil, nil, ErrIncorrectPackage
	}
	off := 0
	coeffs := make([]CoefficientCommitment, t)
	for i := 0; i < t; i++ {
		pt, derr := elemDeserializeCompressed(b[off : off+33])
		if derr != nil {
			return VerifiableSecretSharingCommitment{}, nil, nil, nil, derr
		}
		coeffs[i] = pt
		off += 33
	}
	pop = b[off : off+64]
	off += 64
	pubnonce = b[off : off+33]
	off += 33
	encShares = make([]secp.ModNScalar, n)
	for r := 0; r < n; r++ {
		encShares[r] = modNFromBytesAllowZero(b[off : off+32])
		off += 32
	}
	return VerifiableSecretSharingCommitment{Coeffs: coeffs}, pop, pubnonce, encShares, nil
}

// BIPCoordinatorStep1 is chilldkg.coordinator_step1: it aggregates the round-1
// messages into cmsg1 = coms_to_secrets(33·n) ‖ sum_coms_nonconst(33·(t-1)) ‖
// pops(64·n) ‖ pubnonces(33·n) ‖ enc_secshares(32·n).
func (p SessionParams) BIPCoordinatorStep1(pmsgs [][]byte) ([]byte, error) {
	t, n := int(p.T), len(pmsgs)
	if n != int(p.N) {
		return nil, ErrIncorrectNumberOfPackages
	}

	comsToSecrets := make([][]byte, n)
	pops := make([][]byte, n)
	pubnonces := make([][]byte, n)
	commits := make([]*VerifiableSecretSharingCommitment, n)
	encShares := make([][]secp.ModNScalar, n)
	for i, pm := range pmsgs {
		com, pop, pubnonce, enc, err := parseBIPPmsg1(pm, t, n)
		if err != nil {
			return nil, err
		}
		c := com
		commits[i] = &c
		cb, err := elemSerializeCompressed(com.Coeffs[0])
		if err != nil {
			return nil, err
		}
		comsToSecrets[i], pops[i], pubnonces[i], encShares[i] = cb, pop, pubnonce, enc
	}

	// Summed non-constant terms (group.Coeffs[1:]); coms_to_secrets stay per-sender.
	group, err := sumCommitments(commits)
	if err != nil {
		return nil, err
	}

	// enc_secshares[r] = Σ_i enc_shares[i][r].
	encSecshares := make([]secp.ModNScalar, n)
	for r := 0; r < n; r++ {
		var sum secp.ModNScalar
		for i := 0; i < n; i++ {
			s := encShares[i][r]
			sum.Add(&s)
		}
		encSecshares[r] = sum
	}

	out := make([]byte, 0, 33*n+33*(t-1)+64*n+33*n+32*n)
	for i := 0; i < n; i++ {
		out = append(out, comsToSecrets[i]...)
	}
	for j := 1; j < t; j++ {
		b, err := elemSerializeCompressed(group.Coeffs[j])
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	for i := 0; i < n; i++ {
		out = append(out, pops[i]...)
	}
	for i := 0; i < n; i++ {
		out = append(out, pubnonces[i]...)
	}
	for r := 0; r < n; r++ {
		b := encSecshares[r].Bytes()
		out = append(out, b[:]...)
	}
	return out, nil
}

// parseBIPCmsg1 splits cmsg1 and assembles sum_coms (Coeffs[0]=Σ coms_to_secrets,
// Coeffs[1:]=summed non-constant terms).
func parseBIPCmsg1(b []byte, t, n int) (sumComs VerifiableSecretSharingCommitment, pops, pubnonces [][]byte, encSecshares []secp.ModNScalar, err error) {
	if len(b) != 33*n+33*(t-1)+64*n+33*n+32*n {
		return VerifiableSecretSharingCommitment{}, nil, nil, nil, ErrIncorrectPackage
	}
	off := 0
	pt := func() (secp.JacobianPoint, error) {
		p, e := elemDeserializeCompressed(b[off : off+33])
		off += 33
		return p, e
	}

	sumSecret, err := pt() // coms_to_secrets[0]
	if err != nil {
		return VerifiableSecretSharingCommitment{}, nil, nil, nil, err
	}
	for i := 1; i < n; i++ {
		c, e := pt()
		if e != nil {
			return VerifiableSecretSharingCommitment{}, nil, nil, nil, e
		}
		sumSecret = elemAdd(sumSecret, c)
	}
	coeffs := make([]CoefficientCommitment, t)
	coeffs[0] = sumSecret
	for j := 1; j < t; j++ {
		c, e := pt()
		if e != nil {
			return VerifiableSecretSharingCommitment{}, nil, nil, nil, e
		}
		coeffs[j] = c
	}

	pops = make([][]byte, n)
	for i := 0; i < n; i++ {
		pops[i] = b[off : off+64]
		off += 64
	}
	pubnonces = make([][]byte, n)
	for i := 0; i < n; i++ {
		pubnonces[i] = b[off : off+33]
		off += 33
	}
	encSecshares = make([]secp.ModNScalar, n)
	for i := 0; i < n; i++ {
		encSecshares[i] = modNFromBytesAllowZero(b[off : off+32])
		off += 32
	}
	return VerifiableSecretSharingCommitment{Coeffs: coeffs}, pops, pubnonces, encSecshares, nil
}

// certeqMessage is the message signed in CertEq: a 33-byte zero-padded domain
// prefix ‖ idx(4B) ‖ x (BIP DKG certeq_message).
func certeqMessage(x []byte, idx uint32) []byte {
	prefix := make([]byte, 33)
	copy(prefix, bipTag+"certeq message")
	out := make([]byte, 0, 33+4+len(x))
	out = append(out, prefix...)
	out = append(out, be32(idx)...)
	out = append(out, x...)
	return out
}

// bipEqInput builds the equality-check input: t(4B) ‖ sum_coms ‖ ∥enckeys ‖
// ∥pubnonces ‖ ∥enc_secshares (sum_coms untweaked).
func bipEqInput(t int, sumComs VerifiableSecretSharingCommitment, enckeys, pubnonces [][]byte, encSecshares []secp.ModNScalar) ([]byte, error) {
	sc, err := sumComs.SerializeCompressed()
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, be32(uint32(t))...)
	out = append(out, sc...)
	for _, k := range enckeys {
		out = append(out, k...)
	}
	for _, pn := range pubnonces {
		out = append(out, pn...)
	}
	for i := range encSecshares {
		b := encSecshares[i].Bytes()
		out = append(out, b[:]...)
	}
	return out, nil
}

// BIPParticipantStep2 is chilldkg.participant_step2: from cmsg1 it builds eq_input
// and returns pmsg2, the participant's CertEq signature over it.
func (p SessionParams) BIPParticipantStep2(hostSk *secp.PrivateKey, cmsg1, auxRand []byte) ([]byte, error) {
	t, n := int(p.T), int(p.N)
	enckeys := p.orderedHostPubs()

	hpk := hostSk.PubKey().SerializeCompressed()
	idx := -1
	for i, k := range enckeys {
		if bytes.Equal(k, hpk) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNotInParams
	}

	sumComs, _, pubnonces, encSecshares, err := parseBIPCmsg1(cmsg1, t, n)
	if err != nil {
		return nil, err
	}
	eqInput, err := bipEqInput(t, sumComs, enckeys, pubnonces, encSecshares)
	if err != nil {
		return nil, err
	}
	return bipSchnorrSign(certeqMessage(eqInput, uint32(idx)), hostSk.Serialize(), auxRand, "BIP0340")
}

// BIPDKGOutput is the BIP ChillDKG result (post taproot tweak): the threshold
// public key, per-participant pubshares, and the caller's secshare (nil = coordinator).
type BIPDKGOutput struct {
	ThresholdPubkey []byte   // 33-byte compressed
	Secshare        []byte   // 32-byte big-endian; nil for the coordinator
	Pubshares       [][]byte // n × 33-byte compressed
}

// bipSchnorrVerify is secp256k1lab.bip340.schnorr_verify with a custom tag prefix
// (the verification counterpart of bipSchnorrSign).
func bipSchnorrVerify(msg, pubXonly, sig []byte, tagPrefix string) bool {
	if len(pubXonly) != 32 || len(sig) != 64 {
		return false
	}
	P, err := secp.ParsePubKey(append([]byte{0x02}, pubXonly...))
	if err != nil {
		return false
	}
	var s secp.ModNScalar
	if s.SetByteSlice(sig[32:64]) { // s >= n
		return false
	}
	eh := taggedHash(tagPrefix+"/challenge", sig[0:32], pubXonly, msg)
	e := modNFromBytesAllowZero(eh[:])
	eNeg := e
	eNeg.Negate()
	var pj secp.JacobianPoint
	P.AsJacobian(&pj)
	r := elemAdd(elemBaseMul(&s), elemMul(pj, &eNeg)) // R = s·G − e·P
	if r.Z.IsZero() {
		return false
	}
	r.ToAffine()
	comp := secp.NewPublicKey(&r.X, &r.Y).SerializeCompressed()
	return comp[0] == 0x02 && bytes.Equal(comp[1:], sig[0:32]) // even y and R.x == r
}

// bipCerteqVerify checks the N-of-N CertEq certificate over eqInput (each host key
// signs certeq_message(eqInput, i) under standard BIP340).
func (p SessionParams) bipCerteqVerify(eqInput, cert []byte) error {
	hostpubkeys := p.orderedHostPubs()
	n := len(hostpubkeys)
	if len(cert) != 64*n {
		return ErrInvalidCertSignature
	}
	for i := 0; i < n; i++ {
		msg := certeqMessage(eqInput, uint32(i))
		if !bipSchnorrVerify(msg, hostpubkeys[i][1:33], cert[i*64:(i+1)*64], "BIP0340") {
			return ErrInvalidCertSignature
		}
	}
	return nil
}

// bipTapTweak applies the reference's invalid_taproot_commit: tweak =
// tagged_hash("TapTweak", sum_coms[0]) added to the commitment-to-secret (and to
// each secshare). Returns the tweak scalar and the tweaked commitment.
func bipTapTweak(sumComs VerifiableSecretSharingCommitment) (secp.ModNScalar, VerifiableSecretSharingCommitment, error) {
	pk, err := elemSerializeCompressed(sumComs.Coeffs[0])
	if err != nil {
		return secp.ModNScalar{}, VerifiableSecretSharingCommitment{}, err
	}
	th := taggedHash("TapTweak", pk)
	tweak := modNFromBytesAllowZero(th[:])
	pubtweak := elemBaseMul(&tweak)
	coeffs := make([]CoefficientCommitment, len(sumComs.Coeffs))
	copy(coeffs, sumComs.Coeffs)
	coeffs[0] = elemAdd(coeffs[0], pubtweak)
	return tweak, VerifiableSecretSharingCommitment{Coeffs: coeffs}, nil
}

// bipPads recomputes the recipient's (self's) per-sender decryption pads
// (decaps_multi): selfPad for self, ecdhPadRecv for every other sender.
func (p SessionParams) bipPads(hostSk *secp.PrivateKey, pubnonces [][]byte, idx int) ([]secp.ModNScalar, error) {
	encCtx := encContextBytes(uint32(p.T), p.orderedHostPubs())
	ctx := padContext(uint32(idx), encCtx)
	myHostPub := hostSk.PubKey()
	pads := make([]secp.ModNScalar, int(p.N))
	for j := 0; j < int(p.N); j++ {
		ephPub, err := secp.ParsePubKey(pubnonces[j])
		if err != nil {
			return nil, err
		}
		if j == idx {
			pads[j] = selfPad(hostSk, ephPub, ctx)
		} else {
			pads[j] = ecdhPadRecv(hostSk, ephPub, myHostPub, ctx)
		}
	}
	return pads, nil
}

// bipDecaps decrypts the caller's aggregated secret share from encSecshare:
// encSecshare − Σ pads.
func (p SessionParams) bipDecaps(hostSk *secp.PrivateKey, encSecshare secp.ModNScalar, pubnonces [][]byte, idx int) (secp.ModNScalar, error) {
	pads, err := p.bipPads(hostSk, pubnonces, idx)
	if err != nil {
		return secp.ModNScalar{}, err
	}
	var sumPads secp.ModNScalar
	for j := range pads {
		pad := pads[j]
		sumPads.Add(&pad)
	}
	s := encSecshare
	sumPads.Negate()
	s.Add(&sumPads)
	return s, nil
}

// bipDKGOutput builds the DKGOutput from the tweaked sum commitment: threshold key
// = Coeffs[0], pubshares = GetVerifyingShare at 1..n. secshareTweaked nil = coordinator.
func bipDKGOutput(sumComsTweaked VerifiableSecretSharingCommitment, n int, secshareTweaked *secp.ModNScalar) (BIPDKGOutput, error) {
	tpk, err := elemSerializeCompressed(sumComsTweaked.Coeffs[0])
	if err != nil {
		return BIPDKGOutput{}, err
	}
	pubshares := make([][]byte, n)
	for i := 0; i < n; i++ {
		var x secp.ModNScalar
		x.SetInt(uint32(i + 1))
		id, ierr := NewIdentifier(x)
		if ierr != nil {
			return BIPDKGOutput{}, ierr
		}
		ps, perr := elemSerializeCompressed(sumComsTweaked.GetVerifyingShare(id))
		if perr != nil {
			return BIPDKGOutput{}, perr
		}
		pubshares[i] = ps
	}
	out := BIPDKGOutput{ThresholdPubkey: tpk, Pubshares: pubshares}
	if secshareTweaked != nil {
		b := secshareTweaked.Bytes()
		out.Secshare = b[:]
	}
	return out, nil
}

// BIPParticipantFinalize is chilldkg.participant_finalize: verify the cert (cmsg2),
// decrypt + tweak the caller's share, return the DKGOutput + recovery data (eq_input ‖ cert).
func (p SessionParams) BIPParticipantFinalize(hostSk *secp.PrivateKey, cmsg1, cmsg2 []byte) (BIPDKGOutput, []byte, error) {
	t, n := int(p.T), int(p.N)
	enckeys := p.orderedHostPubs()

	hpk := hostSk.PubKey().SerializeCompressed()
	idx := -1
	for i, k := range enckeys {
		if bytes.Equal(k, hpk) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return BIPDKGOutput{}, nil, ErrNotInParams
	}

	sumComs, _, pubnonces, encSecshares, err := parseBIPCmsg1(cmsg1, t, n)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}
	eqInput, err := bipEqInput(t, sumComs, enckeys, pubnonces, encSecshares)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}
	if err := p.bipCerteqVerify(eqInput, cmsg2); err != nil {
		return BIPDKGOutput{}, nil, err
	}

	secshare, err := p.bipDecaps(hostSk, encSecshares[idx], pubnonces, idx)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}
	tweak, sumComsTweaked, err := bipTapTweak(sumComs)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}
	secshare.Add(&tweak)
	out, err := bipDKGOutput(sumComsTweaked, n, &secshare)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}

	recovery := make([]byte, 0, len(eqInput)+len(cmsg2))
	recovery = append(recovery, eqInput...)
	recovery = append(recovery, cmsg2...)
	return out, recovery, nil
}

// BIPCoordinatorFinalize is chilldkg.coordinator_finalize: assemble the cert from the
// pmsg2 sigs, verify it, return the coordinator DKGOutput (no secshare) + recovery data.
func (p SessionParams) BIPCoordinatorFinalize(cmsg1 []byte, pmsg2s [][]byte) (BIPDKGOutput, []byte, error) {
	t, n := int(p.T), int(p.N)
	enckeys := p.orderedHostPubs()

	sumComs, _, pubnonces, encSecshares, err := parseBIPCmsg1(cmsg1, t, n)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}
	eqInput, err := bipEqInput(t, sumComs, enckeys, pubnonces, encSecshares)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}

	cert := make([]byte, 0, 64*len(pmsg2s))
	for _, s := range pmsg2s {
		cert = append(cert, s...)
	}
	if err := p.bipCerteqVerify(eqInput, cert); err != nil {
		return BIPDKGOutput{}, nil, err
	}

	_, sumComsTweaked, err := bipTapTweak(sumComs)
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}
	out, err := bipDKGOutput(sumComsTweaked, n, nil) // coordinator: no secshare
	if err != nil {
		return BIPDKGOutput{}, nil, err
	}

	recovery := make([]byte, 0, len(eqInput)+len(cert))
	recovery = append(recovery, eqInput...)
	recovery = append(recovery, cert...)
	return out, recovery, nil
}

// bipSessionFromHostpubkeys builds a SessionParams (positional identifiers 1..n)
// from a recovered host-pubkey list and threshold.
func bipSessionFromHostpubkeys(hostpubkeys [][]byte, t uint32) (SessionParams, error) {
	hostPubs := make(map[Identifier]*secp.PublicKey, len(hostpubkeys))
	for i, k := range hostpubkeys {
		var x secp.ModNScalar
		x.SetInt(uint32(i + 1))
		id, err := NewIdentifier(x)
		if err != nil {
			return SessionParams{}, err
		}
		pub, err := secp.ParsePubKey(k)
		if err != nil {
			return SessionParams{}, err
		}
		hostPubs[id] = pub
	}
	return NewSessionParams(uint16(t), hostPubs)
}

// BIPRecover is chilldkg.recover: from a recovery_data blob (eq_input ‖ cert) and a
// host secret key (nil = coordinator), re-derive the params, verify the cert, and
// recover the DKGOutput. Returns the output and the recovered (hostpubkeys, t).
func BIPRecover(hostSk *secp.PrivateKey, recoveryData []byte) (BIPDKGOutput, [][]byte, uint32, error) {
	if len(recoveryData) < 4 {
		return BIPDKGOutput{}, nil, 0, ErrIncorrectPackage
	}
	t := int(binary.BigEndian.Uint32(recoveryData[:4]))
	// len = 4 + 33·t (sum_coms) + 162·n (hostpubkeys+pubnonces+enc_secshares+cert).
	rem := len(recoveryData) - 4 - 33*t
	if t < 1 || rem < 0 || rem%162 != 0 {
		return BIPDKGOutput{}, nil, 0, ErrIncorrectPackage
	}
	n := rem / 162

	off := 4
	coeffs := make([]CoefficientCommitment, t)
	for i := 0; i < t; i++ {
		pt, err := elemDeserializeCompressed(recoveryData[off : off+33])
		if err != nil {
			return BIPDKGOutput{}, nil, 0, err
		}
		coeffs[i] = pt
		off += 33
	}
	sumComs := VerifiableSecretSharingCommitment{Coeffs: coeffs}
	hostpubkeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		hostpubkeys[i] = recoveryData[off : off+33]
		off += 33
	}
	pubnonces := make([][]byte, n)
	for i := 0; i < n; i++ {
		pubnonces[i] = recoveryData[off : off+33]
		off += 33
	}
	encSecshares := make([]secp.ModNScalar, n)
	for i := 0; i < n; i++ {
		encSecshares[i] = modNFromBytesAllowZero(recoveryData[off : off+32])
		off += 32
	}
	cert := recoveryData[off : off+64*n]
	eqInput := recoveryData[:off] // everything before the cert

	params, err := bipSessionFromHostpubkeys(hostpubkeys, uint32(t))
	if err != nil {
		return BIPDKGOutput{}, nil, 0, err
	}
	if err := params.bipCerteqVerify(eqInput, cert); err != nil {
		return BIPDKGOutput{}, nil, 0, err
	}

	tweak, sumComsTweaked, err := bipTapTweak(sumComs)
	if err != nil {
		return BIPDKGOutput{}, nil, 0, err
	}

	// hostSk == nil recovers the coordinator (no secshare); otherwise the key must
	// match a participant, whose share we decrypt and tweak.
	var secsharePtr *secp.ModNScalar
	if hostSk != nil {
		hpk := hostSk.PubKey().SerializeCompressed()
		idx := -1
		for i, k := range hostpubkeys {
			if bytes.Equal(k, hpk) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return BIPDKGOutput{}, nil, 0, ErrNotInParams
		}
		secshare, derr := params.bipDecaps(hostSk, encSecshares[idx], pubnonces, idx)
		if derr != nil {
			return BIPDKGOutput{}, nil, 0, derr
		}
		secshare.Add(&tweak)
		secsharePtr = &secshare
	}

	out, err := bipDKGOutput(sumComsTweaked, n, secsharePtr)
	if err != nil {
		return BIPDKGOutput{}, nil, 0, err
	}
	return out, hostpubkeys, uint32(t), nil
}

// BIPFaultyParticipantError blames a specific participant (by index) — the BIP's
// FaultyParticipantOrCoordinatorError: provably the participant or the coordinator.
type BIPFaultyParticipantError struct {
	Participant int
	Reason      string
}

func (e *BIPFaultyParticipantError) Error() string { return "faulty participant: " + e.Reason }

// BIPFaultyCoordinatorError blames the coordinator.
type BIPFaultyCoordinatorError struct{ Reason string }

func (e *BIPFaultyCoordinatorError) Error() string { return "faulty coordinator: " + e.Reason }

// pointEqual reports whether two (possibly Jacobian) points are equal.
func pointEqual(a, b secp.JacobianPoint) bool { return a.EquivalentNonConst(&b) }

// BIPCoordinatorInvestigate is chilldkg.coordinator_investigate: per recipient i, the
// per-sender enc_partial_secshares(32·n) ‖ partial_pubshares(33·n) (sender j's com at i+1).
func (p SessionParams) BIPCoordinatorInvestigate(pmsgs [][]byte) ([][]byte, error) {
	t, n := int(p.T), len(pmsgs)
	if n != int(p.N) {
		return nil, ErrIncorrectNumberOfPackages
	}
	coms := make([]VerifiableSecretSharingCommitment, n)
	encShares := make([][]secp.ModNScalar, n)
	for j, pm := range pmsgs {
		com, _, _, enc, err := parseBIPPmsg1(pm, t, n)
		if err != nil {
			return nil, err
		}
		coms[j], encShares[j] = com, enc
	}

	cinvs := make([][]byte, n)
	for i := 0; i < n; i++ { // recipient i
		var x secp.ModNScalar
		x.SetInt(uint32(i + 1))
		id, err := NewIdentifier(x)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, 32*n+33*n)
		for j := 0; j < n; j++ { // enc_partial_secshares
			b := encShares[j][i].Bytes()
			out = append(out, b[:]...)
		}
		for j := 0; j < n; j++ { // partial_pubshares: sender j's pubshare at i
			ps, perr := elemSerializeCompressed(coms[j].GetVerifyingShare(id))
			if perr != nil {
				return nil, perr
			}
			out = append(out, ps...)
		}
		cinvs[i] = out
	}
	return cinvs, nil
}

// parseBIPCinv splits a coordinator investigation message into the per-sender
// encrypted partial shares (32·n) and partial pubshares (33·n).
func parseBIPCinv(b []byte, n int) ([]secp.ModNScalar, []secp.JacobianPoint, error) {
	if len(b) != 32*n+33*n {
		return nil, nil, ErrIncorrectPackage
	}
	off := 0
	encPartial := make([]secp.ModNScalar, n)
	for i := 0; i < n; i++ {
		encPartial[i] = modNFromBytesAllowZero(b[off : off+32])
		off += 32
	}
	partialPub := make([]secp.JacobianPoint, n)
	for i := 0; i < n; i++ {
		pt, err := elemDeserializeCompressed(b[off : off+33])
		if err != nil {
			return nil, nil, err
		}
		partialPub[i] = pt
		off += 33
	}
	return encPartial, partialPub, nil
}

// BIPParticipantInvestigate is participant_investigate: it attributes blame for the
// caller's failed share, always returning a verdict (*BIPFaultyParticipantError or
// *BIPFaultyCoordinatorError). A sender is pinned only when provably inconsistent.
func (p SessionParams) BIPParticipantInvestigate(hostSk *secp.PrivateKey, cmsg1, cinv []byte) error {
	t, n := int(p.T), int(p.N)
	enckeys := p.orderedHostPubs()

	hpk := hostSk.PubKey().SerializeCompressed()
	idx := -1
	for i, k := range enckeys {
		if bytes.Equal(k, hpk) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrNotInParams
	}

	sumComs, _, pubnonces, encSecshares, err := parseBIPCmsg1(cmsg1, t, n)
	if err != nil {
		return err
	}
	pads, err := p.bipPads(hostSk, pubnonces, idx)
	if err != nil {
		return err
	}

	// secshare = enc_secshares[idx] − Σ pads (untweaked).
	var sumPads secp.ModNScalar
	for j := range pads {
		pad := pads[j]
		sumPads.Add(&pad)
	}
	secshare := encSecshares[idx]
	negSum := sumPads
	negSum.Negate()
	secshare.Add(&negSum)

	// pubshare = sum_coms evaluated at idx+1 (untweaked).
	var x secp.ModNScalar
	x.SetInt(uint32(idx + 1))
	id, err := NewIdentifier(x)
	if err != nil {
		return err
	}
	pubshare := sumComs.GetVerifyingShare(id)

	encPartial, partialPub, err := parseBIPCinv(cinv, n)
	if err != nil {
		return err
	}
	// partial_secshares[j] = enc_partial[j] − pads[j].
	partialSec := make([]secp.ModNScalar, n)
	for j := 0; j < n; j++ {
		s := encPartial[j]
		pad := pads[j]
		pad.Negate()
		s.Add(&pad)
		partialSec[j] = s
	}

	// (a) Σ partial_pubshares must equal pubshare.
	var sumPub secp.JacobianPoint // infinity
	for j := 0; j < n; j++ {
		sumPub = elemAdd(sumPub, partialPub[j])
	}
	if !pointEqual(sumPub, pubshare) {
		return &BIPFaultyCoordinatorError{Reason: "Sum of partial pubshares not equal to pubshare"}
	}
	// (b) Σ partial_secshares must equal secshare (else the coordinator altered the
	// encrypted partial shares, by additive homomorphism).
	var sumSec secp.ModNScalar
	for j := 0; j < n; j++ {
		s := partialSec[j]
		sumSec.Add(&s)
	}
	if !sumSec.Equals(&secshare) {
		return &BIPFaultyCoordinatorError{Reason: "Sum of encrypted partial secshares not equal to encrypted secshare"}
	}
	// (c) each partial secshare must match its partial pubshare; the first failure
	// pins the sender (or the coordinator, if it is the caller's own share).
	for j := 0; j < n; j++ {
		if !pointEqual(elemBaseMul(&partialSec[j]), partialPub[j]) {
			if j != idx {
				return &BIPFaultyParticipantError{Participant: j, Reason: "Participant sent invalid partial secshare"}
			}
			return &BIPFaultyCoordinatorError{Reason: "Coordinator fiddled with the share from me to myself"}
		}
	}
	return &BIPFaultyCoordinatorError{Reason: "consistent partial shares but share failed verification"}
}
