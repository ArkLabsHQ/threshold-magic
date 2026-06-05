package thresholdcore

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// EncPedPop masks each PedPop share with an additive pad so shares can travel
// over an untrusted channel: ciphertext = f_i(ℓ) + pad_iℓ (mod n). The pads are
// additive, so the coordinator can sum ciphertexts per recipient without
// learning anything; the recipient subtracts the pads and verifies the result
// against the summed VSS commitment. (See bip-frost-dkg EncPedPop.)

// Domain-separation tags for the tagged hash. Both encryption pads follow the
// reference's BIP-FROST-DKG construction byte-for-byte — same tags, same
// SHA256-of-compressed-point ECDH, and the same per-recipient context_ (see
// encryptionContext/padContext). Only tagRound2 (our per-share authentication
// signature, not part of the BIP) stays library-specific.
const (
	tagEcdhPad = "BIP DKG/encpedpop ecdh"
	tagSelfPad = "BIP DKG/encaps_multi self_pad"
	tagRound2  = "thresholdmagic/encpedpop/round2"
)

var (
	// ErrMissingHostKey is returned when a recipient's host public key is absent.
	ErrMissingHostKey = errors.New("missing host public key for recipient")
	// ErrMissingEphKey is returned when a sender's ephemeral public key is absent.
	ErrMissingEphKey = errors.New("missing ephemeral public key for sender")
	// ErrInfinityVerifyingKey is returned when the aggregated group key is the
	// point at infinity (sum of secrets ≡ 0 mod n).
	ErrInfinityVerifyingKey = errors.New("group verifying key is the point at infinity")
)

// taggedHash is the BIP340 tagged hash SHA256(SHA256(tag)||SHA256(tag)||parts),
// delegated to btcec's chainhash (the same implementation btcec's schnorr uses).
func taggedHash(tag string, parts ...[]byte) [32]byte {
	return [32]byte(*chainhash.TaggedHash([]byte(tag), parts...))
}

// EphemeralKey is a per-session ECDH keypair used to derive encryption pads.
type EphemeralKey struct {
	Sk  *secp.PrivateKey
	Pub *secp.PublicKey
}

// NewEphemeralKey generates a fresh ephemeral keypair from r.
func NewEphemeralKey(r io.Reader) (EphemeralKey, error) {
	sk, err := secp.GeneratePrivateKeyFromRand(r)
	if err != nil {
		return EphemeralKey{}, err
	}
	return EphemeralKey{Sk: sk, Pub: sk.PubKey()}, nil
}

// ecdhShared mirrors the reference's ecdh_libsecp256k1: SHA256 of the COMPRESSED
// shared point sk·pub. (dcrec's GenerateSharedSecret returns the raw x-coordinate,
// so we compute the point and hash its compressed encoding ourselves.)
func ecdhShared(sk *secp.PrivateKey, pub *secp.PublicKey) [32]byte {
	var pj, shared secp.JacobianPoint
	pub.AsJacobian(&pj)
	secp.ScalarMultNonConst(&sk.Key, &pj, &shared)
	shared.ToAffine()
	return sha256.Sum256(secp.NewPublicKey(&shared.X, &shared.Y).SerializeCompressed())
}

// encryptionContext mirrors the reference's serialize_enc_context(t, enckeys):
// t(4B BE) ‖ concat(host pubkeys in IDs() order). idxOf maps each identifier to
// its position in that order, used as the per-recipient prefix (see padContext).
// enckeys are the participants' host public keys (our long-lived keys serve as the
// reference's enc/dec keys), so this binds every pad to the full ordered key set.
func (p SessionParams) encryptionContext() (encCtx []byte, idxOf map[Identifier]uint32) {
	ids := p.IDs()
	pubs := make([][]byte, len(ids))
	idxOf = make(map[Identifier]uint32, len(ids))
	for i, id := range ids {
		idxOf[id] = uint32(i)
		pubs[i] = p.HostPubs[id].SerializeCompressed()
	}
	return encContextBytes(uint32(p.T), pubs), idxOf
}

// padContext builds the reference's per-recipient context_ for encaps_multi /
// decaps_multi: recipientIndex(4B BE) ‖ encCtx. The recipient's index is always
// prefixed (the sender prefixes each recipient's; the recipient prefixes its own),
// so sender and recipient derive byte-identical context for the same pad.
func padContext(recipientIndex uint32, encCtx []byte) []byte {
	out := make([]byte, u32Len+len(encCtx))
	binary.BigEndian.PutUint32(out[:u32Len], recipientIndex)
	copy(out[u32Len:], encCtx)
	return out
}

// padFromECDH derives the scalar pad exactly as the reference's ecdh():
// tagged_hash("BIP DKG/encpedpop ecdh", ecdh ‖ ephPub ‖ hostPub ‖ context). Both
// parties order the keys ephemeral-then-host (the reference's my‖their / their‖my
// resolve to the same bytes), so sender and recipient derive the same pad; context
// is the reference's per-recipient context_ (see padContext).
func padFromECDH(ecdh [32]byte, ephPub, recipientHostPub *secp.PublicKey, context []byte) secp.ModNScalar {
	h := taggedHash(
		tagEcdhPad,
		ecdh[:],
		ephPub.SerializeCompressed(),
		recipientHostPub.SerializeCompressed(),
		context,
	)
	return modNFromBytesAllowZero(h[:])
}

// ecdhPadSend computes pad_iℓ from the sender's perspective.
func ecdhPadSend(ephSk *secp.PrivateKey, ephPub, recipientHostPub *secp.PublicKey, context []byte) secp.ModNScalar {
	return padFromECDH(ecdhShared(ephSk, recipientHostPub), ephPub, recipientHostPub, context)
}

// ecdhPadRecv computes pad_iℓ from the recipient's perspective.
func ecdhPadRecv(recipientHostSk *secp.PrivateKey, ephPub, recipientHostPub *secp.PublicKey, context []byte) secp.ModNScalar {
	return padFromECDH(ecdhShared(recipientHostSk, ephPub), ephPub, recipientHostPub, context)
}

// selfPad masks the share a participant produces for itself (i == ℓ). No ECDH:
// the same party adds and removes it, so a keyed hash of its own secret suffices.
// It follows the reference's self_pad(symkey=deckey, nonce=pubnonce, context):
// the party's host secret, its own ephemeral key, then the per-recipient context_
// — so the pad is unique per ceremony (the ephemeral key is fresh) and bound to the
// full ordered key set.
func selfPad(hostSk *secp.PrivateKey, ephPub *secp.PublicKey, context []byte) secp.ModNScalar {
	skb := hostSk.Serialize()
	h := taggedHash(tagSelfPad, skb, ephPub.SerializeCompressed(), context)
	return modNFromBytesAllowZero(h[:])
}

// AuthenticatedShare is one sender's ciphertext for one recipient, signed under
// the sender's host key so the recipient can confirm during investigation that it
// came from that sender unaltered (a relaying coordinator cannot forge it).
type AuthenticatedShare struct {
	Ciphertext secp.ModNScalar
	Sig        *schnorr.Signature
}

// round2SigHash binds a ciphertext to its sender, recipient, session, and the
// sender's ephemeral key (the last prevents an ephemeral-key swap from reframing it).
func round2SigHash(sessionID []byte, sender, recipient Identifier, ephPub *secp.PublicKey, ct secp.ModNScalar) [32]byte {
	ctb := ct.Bytes()
	return taggedHash(
		tagRound2,
		sessionID,
		sender.Serialize(),
		recipient.Serialize(),
		ephPub.SerializeCompressed(),
		ctb[:],
	)
}

// SignRound2Share produces the sender's BIP340 signature authenticating a round-2
// ciphertext. It is applied automatically by EncPedPopRound2.
func SignRound2Share(hostSk *secp.PrivateKey, sessionID []byte, sender, recipient Identifier, ephPub *secp.PublicKey, ct secp.ModNScalar) (*schnorr.Signature, error) {
	h := round2SigHash(sessionID, sender, recipient, ephPub, ct)
	return schnorr.Sign(hostSk, h[:])
}

// VerifyRound2Share verifies a SignRound2Share signature under the sender's host key.
func VerifyRound2Share(hostPub *secp.PublicKey, sessionID []byte, sender, recipient Identifier, ephPub *secp.PublicKey, ct secp.ModNScalar, sig *schnorr.Signature) bool {
	if sig == nil || hostPub == nil || ephPub == nil {
		return false
	}
	h := round2SigHash(sessionID, sender, recipient, ephPub, ct)
	return sig.Verify(h[:], hostPub)
}

// EncRound2 holds one sender's per-recipient authenticated ciphertexts, keyed by
// recipient and including the sender's own entry (masked with selfPad) so the
// coordinator sums uniformly over all N.
type EncRound2 struct {
	Shares map[Identifier]AuthenticatedShare
}

// EncPedPopRound2 runs DKGPart2, masks each share with its reference-style pad, and
// signs each ciphertext under hostSk (the sender's host key) for later
// authentication. The pads use the reference's per-recipient context_ derived from
// p (see encryptionContext/padContext); p.SessionID still binds the per-share
// authentication signature.
func EncPedPopRound2(
	r1secret Round1SecretPackage,
	round1Pkgs map[Identifier]Round1Package,
	eph EphemeralKey,
	hostSk *secp.PrivateKey,
	p SessionParams,
) (Round2SecretPackage, EncRound2, error) {

	r2secret, plainShares, err := DKGPart2(r1secret, round1Pkgs)
	if err != nil {
		return Round2SecretPackage{}, EncRound2{}, err
	}

	sender := r1secret.Identifier
	encCtx, idxOf := p.encryptionContext()
	shares := make(map[Identifier]AuthenticatedShare, len(plainShares)+1)

	add := func(recipient Identifier, c secp.ModNScalar) error {
		sig, err := SignRound2Share(hostSk, p.SessionID, sender, recipient, eph.Pub, c)
		if err != nil {
			return err
		}
		shares[recipient] = AuthenticatedShare{Ciphertext: c, Sig: sig}
		return nil
	}

	// Peers: ECDH pad, with the recipient's index prefixed to enc_context.
	for recipient, pkg := range plainShares {
		hostPub, ok := p.HostPubs[recipient]
		if !ok {
			return Round2SecretPackage{}, EncRound2{}, ErrMissingHostKey
		}
		pad := ecdhPadSend(eph.Sk, eph.Pub, hostPub, padContext(idxOf[recipient], encCtx))
		c := (secp.ModNScalar)(pkg.SecretShare)
		c.Add(&pad)
		if err := add(recipient, c); err != nil {
			return Round2SecretPackage{}, EncRound2{}, err
		}
	}

	// Self: symmetric pad over f_i(i), under this party's own index.
	selfP := selfPad(hostSk, eph.Pub, padContext(idxOf[sender], encCtx))
	selfShare := r2secret.SecretShare // value copy
	selfShare.Add(&selfP)
	if err := add(sender, selfShare); err != nil {
		return Round2SecretPackage{}, EncRound2{}, err
	}

	return r2secret, EncRound2{Shares: shares}, nil
}

// AggregateCiphertexts sums, per recipient, the ciphertexts from every sender.
// ids must list all N participants. (Signatures are verified only on investigation.)
func AggregateCiphertexts(perSender map[Identifier]EncRound2, ids []Identifier) (map[Identifier]secp.ModNScalar, error) {
	out := make(map[Identifier]secp.ModNScalar, len(ids))
	for _, recipient := range ids {
		var sum secp.ModNScalar
		for _, sender := range ids {
			er, ok := perSender[sender]
			if !ok {
				return nil, ErrIncorrectPackage
			}
			share, ok := er.Shares[recipient]
			if !ok {
				return nil, ErrIncorrectPackage
			}
			c := share.Ciphertext
			sum.Add(&c)
		}
		out[recipient] = sum
	}
	return out, nil
}

// DecryptAndVerifyShare recovers a recipient's share by subtracting the sum of
// pads, then verifies g^{s_ℓ} against the group VSS commitment. p supplies the full
// participant set (p.IDs(), including self) and the reference encryption context;
// group is the summed commitment. As in the reference's decaps_multi, every pad
// shares one context_ keyed by the recipient's (self's) index.
func DecryptAndVerifyShare(
	self Identifier,
	encSecshare secp.ModNScalar,
	p SessionParams,
	ephPubs map[Identifier]*secp.PublicKey,
	myHostSk *secp.PrivateKey,
	group VerifiableSecretSharingCommitment,
) (SecretShare, error) {

	// Reject a point-at-infinity group key.
	vk, err := group.ToVerifyingKey()
	if err != nil {
		return SecretShare(modNZero()), err
	}
	if isInfinity(vk.E) {
		return SecretShare(modNZero()), ErrInfinityVerifyingKey
	}

	myHostPub := myHostSk.PubKey()
	encCtx, idxOf := p.encryptionContext()
	ctx := padContext(idxOf[self], encCtx)

	var sumPads secp.ModNScalar
	for _, sender := range p.IDs() {
		if sender.Equal(self) {
			ephPub, ok := ephPubs[self]
			if !ok {
				return SecretShare(modNZero()), ErrMissingEphKey
			}
			pad := selfPad(myHostSk, ephPub, ctx)
			sumPads.Add(&pad)
			continue
		}
		ephPub, ok := ephPubs[sender]
		if !ok {
			return SecretShare(modNZero()), ErrMissingEphKey
		}
		pad := ecdhPadRecv(myHostSk, ephPub, myHostPub, ctx)
		sumPads.Add(&pad)
	}

	// s_ℓ = encSecshare − Σ pads
	s := encSecshare
	sumPads.Negate()
	s.Add(&sumPads)

	// g^{s_ℓ} must equal the recipient's share of the group commitment.
	left := elemBaseMul(&s)
	right := group.GetVerifyingShare(self)
	if !left.EquivalentNonConst(&right) {
		return SecretShare(modNZero()), ErrInvalidSecretShare
	}

	return SecretShare(s), nil
}

// isInfinity reports whether a Jacobian point is the identity element. dcrec uses
// two representations: the canonical Jacobian infinity (Z == 0) and the affine point
// (0, 0) with Z != 0 (e.g. the result of ScalarBaseMultNonConst(0) = g^0). Both are
// detected. No valid curve point has both affine coordinates zero — x = 0 admits
// only y = ±√7 != 0 — so the affine-(0,0) test is exact.
func isInfinity(p secp.JacobianPoint) bool {
	if p.Z.IsZero() {
		return true
	}
	a := p
	a.ToAffine()
	return a.X.IsZero() && a.Y.IsZero()
}

// BIP-exact EncPedPop (bip-frost-dkg): byte-exact encryption/hashing for the BIP
// wire, validated against the upstream vectors. The hybrid's AuthenticatedShare
// signatures ride alongside the BIP message, never inside these bytes.

const bipTag = "BIP DKG/" // tagged_hash_bip_dkg domain prefix

var (
	// ErrSeckeyLen is returned when a host secret key is not 32 bytes.
	ErrSeckeyLen = errors.New("host secret key must be 32 bytes")
	// ErrSeckeyRange is returned when a secret key is not in 1..n-1.
	ErrSeckeyRange = errors.New("secret key out of range 1..n-1")
	// ErrNotInParams is returned when a host pubkey is absent from the params.
	ErrNotInParams = errors.New("host pubkey not among params")
	// ErrNonceZero is returned when a derived nonce is zero (negligible).
	ErrNonceZero = errors.New("derived nonce is zero (negligible)")
)

// bipHash is tagged_hash_bip_dkg(tag, parts...) = taggedHash("BIP DKG/"+tag, …).
func bipHash(tag string, parts ...[]byte) [32]byte {
	return taggedHash(bipTag+tag, parts...)
}

// be32 encodes x as 4 big-endian bytes.
func be32(x uint32) []byte {
	b := make([]byte, u32Len)
	binary.BigEndian.PutUint32(b, x)
	return b
}

// xonly returns a point's 32-byte x-coordinate.
func xonly(p secp.JacobianPoint) ([]byte, error) {
	b, err := elemSerializeCompressed(p)
	if err != nil {
		return nil, err
	}
	return b[1:], nil
}

// encContextBytes is serialize_enc_context: t(4B BE) ‖ ∥enckeys (participant order).
func encContextBytes(t uint32, orderedHostPubs [][]byte) []byte {
	out := make([]byte, 0, 4+len(orderedHostPubs)*33)
	out = append(out, be32(t)...)
	for _, k := range orderedHostPubs {
		out = append(out, k...)
	}
	return out
}

// BIP340 tagged-hash sub-tags, appended to a signature's tag prefix (e.g. tagBIP340
// or bipTag+labelPopMessage) to form the aux/nonce/challenge hash domains.
const (
	subtagAux       = "/aux"
	subtagNonce     = "/nonce"
	subtagChallenge = "/challenge"
)

// bipSchnorrSign is a deterministic BIP340 signature over msg, where tagPrefix is
// the full aux/nonce/challenge tag prefix ("BIP0340" for CertEq, "BIP DKG/pop
// message" for the proof-of-possession).
func bipSchnorrSign(msg, seckey, auxRand []byte, tagPrefix string) ([]byte, error) {
	var d0 secp.ModNScalar
	if d0.SetByteSlice(seckey) || d0.IsZero() {
		return nil, ErrSeckeyRange
	}
	pj := elemBaseMul(&d0)
	pj.ToAffine()
	d := d0
	if pj.Y.IsOdd() {
		d.Negate()
	}
	px, err := xonly(pj)
	if err != nil {
		return nil, err
	}

	// t = bytes(d) XOR tagged_hash(tag/aux, aux_rand)
	db := d.Bytes()
	aux := taggedHash(tagPrefix+subtagAux, auxRand)
	var tt [32]byte
	for i := 0; i < scalarLen; i++ {
		tt[i] = db[i] ^ aux[i]
	}

	// k0 = int(tagged_hash(tag/nonce, t ‖ Px ‖ msg)) mod n
	nh := taggedHash(tagPrefix+subtagNonce, tt[:], px, msg)
	k0 := modNFromBytesAllowZero(nh[:])
	if k0.IsZero() {
		return nil, ErrNonceZero
	}
	rj := elemBaseMul(&k0)
	rj.ToAffine()
	k := k0
	if rj.Y.IsOdd() {
		k.Negate()
	}
	rx, err := xonly(rj)
	if err != nil {
		return nil, err
	}

	// e = int(tagged_hash(tag/challenge, Rx ‖ Px ‖ msg)) mod n
	eh := taggedHash(tagPrefix+subtagChallenge, rx, px, msg)
	e := modNFromBytesAllowZero(eh[:])

	// s = (k + e·d) mod n
	var s secp.ModNScalar
	s.Mul2(&e, &d).Add(&k)
	sb := s.Bytes()

	sig := make([]byte, schnorrSigLen)
	copy(sig[:scalarLen], rx)
	copy(sig[scalarLen:], sb[:])
	return sig, nil
}

// bipEncryptMulti is encpedpop.encrypt_multi: ciphertext[i] = plaintext[i] + pad,
// using selfPad for i==idx and ecdhPadSend otherwise.
func bipEncryptMulti(secnoncePriv, deckeyPriv *secp.PrivateKey, pubnoncePub *secp.PublicKey, enckeys [][]byte, encCtx []byte, idx int, plaintexts []secp.ModNScalar) ([]secp.ModNScalar, error) {
	cts := make([]secp.ModNScalar, len(enckeys))
	for i, enckey := range enckeys {
		ctx := padContext(uint32(i), encCtx)
		var pad secp.ModNScalar
		if i == idx {
			pad = selfPad(deckeyPriv, pubnoncePub, ctx)
		} else {
			ek, err := secp.ParsePubKey(enckey)
			if err != nil {
				return nil, err
			}
			pad = ecdhPadSend(secnoncePriv, pubnoncePub, ek, ctx)
		}
		c := plaintexts[i]
		c.Add(&pad)
		cts[i] = c
	}
	return cts, nil
}
