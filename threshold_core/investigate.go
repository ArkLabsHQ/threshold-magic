package thresholdcore

import (
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Blame / investigation sub-protocol (bip-frost-dkg participant_investigate):
// when a recipient's aggregate share fails, the coordinator reveals the
// per-sender ciphertexts and the recipient pins the culprit.

// FaultyParticipantError blames a specific participant for a share inconsistent
// with its public VSS commitment.
type FaultyParticipantError struct {
	Culprit Identifier
	Reason  string
}

func (e *FaultyParticipantError) Error() string {
	return fmt.Sprintf("faulty participant %s: %s", e.Culprit, e.Reason)
}

// FaultyCoordinatorError blames the coordinator (inconsistent aggregate, altered
// self-share, or otherwise unattributable to a single sender).
type FaultyCoordinatorError struct {
	Reason string
}

func (e *FaultyCoordinatorError) Error() string {
	return "faulty coordinator: " + e.Reason
}

// PartialCiphertextsFor extracts, for a single recipient, the per-sender
// ciphertexts c_iℓ from the coordinator's collected round-2 messages. senders
// should be the full participant set (SessionParams.IDs()).
func PartialCiphertextsFor(
	perSender map[Identifier]EncRound2,
	recipient Identifier,
	senders []Identifier,
) (map[Identifier]AuthenticatedShare, error) {
	out := make(map[Identifier]AuthenticatedShare, len(senders))
	for _, s := range senders {
		er, ok := perSender[s]
		if !ok {
			return nil, ErrIncorrectPackage
		}
		sh, ok := er.Shares[recipient]
		if !ok {
			return nil, ErrIncorrectPackage
		}
		out[s] = sh
	}
	return out, nil
}

// InvestigateShare attributes a failed aggregate share, called by recipient
// `self` after DecryptAndVerifyShare returned ErrInvalidSecretShare. round1All
// and ephPubs must be the recipient's cmsg1-retained values; the participant set,
// session id, and host keys come from p. A sender is blamed only on cryptographic
// proof — a validly signed ciphertext inconsistent with its VSS commitment;
// anything unprovable (a missing/invalid signature, a wrong aggregate) blames the
// coordinator, so an honest sender is never framed even against a malicious one.
// Returns *FaultyParticipantError, *FaultyCoordinatorError, or
// ErrInfinityVerifyingKey (a zero-sum group key, which blames no one).
func InvestigateShare(
	p SessionParams,
	self Identifier,
	encSecshare secp.ModNScalar,
	partial map[Identifier]AuthenticatedShare,
	ephPubs map[Identifier]*secp.PublicKey,
	myHostSk *secp.PrivateKey,
	round1All map[Identifier]Round1Package,
) error {

	senders := p.IDs()

	// Infinity guard: a zero-sum group key is no one's fault.
	list := make([]*VerifiableSecretSharingCommitment, 0, len(senders))
	for _, id := range senders {
		r1, ok := round1All[id]
		if !ok {
			return ErrIncorrectPackage
		}
		c := r1.Commitment
		list = append(list, &c)
	}
	group, err := sumCommitments(list)
	if err != nil {
		return err
	}
	vk, err := group.ToVerifyingKey()
	if err != nil {
		return err
	}
	if isInfinity(vk.E) {
		return ErrInfinityVerifyingKey
	}

	// Authenticate each revealed ciphertext under its sender's host key and sum
	// them; an absent/unknown/unverifiable share blames the coordinator (it cannot
	// forge a sender's signature).
	var sum secp.ModNScalar
	for _, id := range senders {
		sh, ok := partial[id]
		if !ok {
			return &FaultyCoordinatorError{Reason: "missing per-sender ciphertext"}
		}
		ephPub, ok := ephPubs[id]
		if !ok {
			return ErrMissingEphKey
		}
		hostPub, ok := p.HostPubs[id]
		if !ok {
			return ErrUnknownIdentifier
		}
		if !VerifyRound2Share(hostPub, p.SessionID, id, self, ephPub, sh.Ciphertext, sh.Sig) {
			return &FaultyCoordinatorError{Reason: "unauthenticated or altered share for sender " + id.String()}
		}
		c := sh.Ciphertext
		sum.Add(&c)
	}
	if !sum.Equals(&encSecshare) {
		return &FaultyCoordinatorError{Reason: "revealed ciphertexts do not sum to the aggregate"}
	}

	// Per-sender check in sorted order (deterministic culprit). Each ciphertext is
	// now authenticated, so a failure is a genuinely faulty sender.
	myHostPub := myHostSk.PubKey()
	for _, id := range senders {
		var pad secp.ModNScalar
		if id.Equal(self) {
			pad = selfPad(myHostSk, p.SessionID, ephPubs[id])
		} else {
			pad = ecdhPadRecv(myHostSk, ephPubs[id], myHostPub, p.SessionID)
		}

		// f_i(self) = c_iℓ − pad_iℓ
		fi := partial[id].Ciphertext
		pad.Negate()
		fi.Add(&pad)

		ts := ThresholdShare{
			Identifier: self,
			SecretSh:   SecretShare(fi),
			Commitment: round1All[id].Commitment,
		}
		if _, _, verr := ts.Verify(); verr != nil {
			if id.Equal(self) {
				// An honest recipient never signs a bad self-share; blame the coordinator.
				return &FaultyCoordinatorError{Reason: "altered self-share"}
			}
			return &FaultyParticipantError{Culprit: id, Reason: "share inconsistent with VSS commitment"}
		}
	}

	// Defensive: authentic parts that sum and verify should not reach here.
	return &FaultyCoordinatorError{Reason: "consistent partial shares but aggregate failed verification"}
}
