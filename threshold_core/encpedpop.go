package thresholdcore

import (
	"crypto/sha256"
	"errors"
	"io"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// EncPedPop masks each PedPop share with an additive pad so shares can travel
// over an untrusted channel: ciphertext = f_i(ℓ) + pad_iℓ (mod n). The pads are
// additive, so the coordinator can sum ciphertexts per recipient without
// learning anything; the recipient subtracts the pads and verifies the result
// against the summed VSS commitment. (See bip-frost-dkg EncPedPop.)

// Domain-separation tags for the tagged hash (library-specific, not BIP-wire-compatible).
const (
	tagEcdhPad = "thresholdmagic/encpedpop/ecdh"
	tagSelfPad = "thresholdmagic/encpedpop/self"
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

// taggedHash is the BIP340-style tagged hash: SHA256(SHA256(tag)||SHA256(tag)||parts).
func taggedHash(tag string, parts ...[]byte) [32]byte {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
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

// padFromECDH derives the scalar pad, binding the ephemeral key, recipient host
// key, session id, and the ECDH x-coordinate. Sender and recipient reach the
// same shared secret and so derive the same pad.
func padFromECDH(ephPub, recipientHostPub *secp.PublicKey, sessionID, sharedX []byte) secp.ModNScalar {
	h := taggedHash(
		tagEcdhPad,
		ephPub.SerializeCompressed(),
		recipientHostPub.SerializeCompressed(),
		sessionID,
		sharedX,
	)
	return modNFromBytesAllowZero(h[:])
}

// ecdhPadSend computes pad_iℓ from the sender's perspective.
func ecdhPadSend(ephSk *secp.PrivateKey, ephPub, recipientHostPub *secp.PublicKey, sessionID []byte) secp.ModNScalar {
	sharedX := secp.GenerateSharedSecret(ephSk, recipientHostPub)
	return padFromECDH(ephPub, recipientHostPub, sessionID, sharedX)
}

// ecdhPadRecv computes pad_iℓ from the recipient's perspective.
func ecdhPadRecv(recipientHostSk *secp.PrivateKey, ephPub, recipientHostPub *secp.PublicKey, sessionID []byte) secp.ModNScalar {
	sharedX := secp.GenerateSharedSecret(recipientHostSk, ephPub)
	return padFromECDH(ephPub, recipientHostPub, sessionID, sharedX)
}

// selfPad masks the share a participant produces for itself (i == ℓ). No ECDH:
// the same party adds and removes it, so a keyed hash of its own secret suffices.
func selfPad(hostSk *secp.PrivateKey, sessionID []byte) secp.ModNScalar {
	skb := hostSk.Serialize()
	h := taggedHash(tagSelfPad, skb, sessionID)
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

// EncPedPopRound2 runs DKGPart2, masks each share with its pad, and signs each
// ciphertext under hostSk (the sender's host key) for later authentication.
// hostPubs maps each recipient to its host public key.
func EncPedPopRound2(
	r1secret Round1SecretPackage,
	round1Pkgs map[Identifier]Round1Package,
	eph EphemeralKey,
	hostSk *secp.PrivateKey,
	hostPubs map[Identifier]*secp.PublicKey,
	sessionID []byte,
) (Round2SecretPackage, EncRound2, error) {

	r2secret, plainShares, err := DKGPart2(r1secret, round1Pkgs)
	if err != nil {
		return Round2SecretPackage{}, EncRound2{}, err
	}

	sender := r1secret.Identifier
	shares := make(map[Identifier]AuthenticatedShare, len(plainShares)+1)

	add := func(recipient Identifier, c secp.ModNScalar) error {
		sig, err := SignRound2Share(hostSk, sessionID, sender, recipient, eph.Pub, c)
		if err != nil {
			return err
		}
		shares[recipient] = AuthenticatedShare{Ciphertext: c, Sig: sig}
		return nil
	}

	// Peers: ECDH pad.
	for recipient, pkg := range plainShares {
		hostPub, ok := hostPubs[recipient]
		if !ok {
			return Round2SecretPackage{}, EncRound2{}, ErrMissingHostKey
		}
		pad := ecdhPadSend(eph.Sk, eph.Pub, hostPub, sessionID)
		c := (secp.ModNScalar)(pkg.SecretShare)
		c.Add(&pad)
		if err := add(recipient, c); err != nil {
			return Round2SecretPackage{}, EncRound2{}, err
		}
	}

	// Self: symmetric pad over f_i(i).
	selfP := selfPad(hostSk, sessionID)
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
// pads, then verifies g^{s_ℓ} against the group VSS commitment. senders must
// list all N identifiers (including self); group is the summed commitment.
func DecryptAndVerifyShare(
	self Identifier,
	encSecshare secp.ModNScalar,
	senders []Identifier,
	ephPubs map[Identifier]*secp.PublicKey,
	myHostSk *secp.PrivateKey,
	sessionID []byte,
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

	var sumPads secp.ModNScalar
	for _, sender := range senders {
		if sender.Equal(self) {
			p := selfPad(myHostSk, sessionID)
			sumPads.Add(&p)
			continue
		}
		ephPub, ok := ephPubs[sender]
		if !ok {
			return SecretShare(modNZero()), ErrMissingEphKey
		}
		p := ecdhPadRecv(myHostSk, ephPub, myHostPub, sessionID)
		sumPads.Add(&p)
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

// isInfinity reports whether a Jacobian point is the point at infinity (Z == 0).
func isInfinity(p secp.JacobianPoint) bool {
	return p.Z.IsZero()
}
