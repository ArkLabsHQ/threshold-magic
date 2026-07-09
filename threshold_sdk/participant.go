package thresholdsdk

import (
	"context"
	"errors"
	"io"

	thres "github.com/ArkLabsHQ/threshold-magic/threshold_core"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// participant runs the key-holder side of the BIP ChillDKG protocol over a
// Transport: pmsg1 → cmsg1 → pmsg2 → cmsg2 → finalize.
type participant struct {
	Params    thres.SessionParams
	Self      thres.Identifier
	HostSk    *secp.PrivateKey
	Rng       io.Reader
	Transport Transport
	// CoordAddr is the coordinator's transport address (defaults to CoordinatorAddr).
	CoordAddr string

	// Leader/follower config — an SDK setting, NOT part of SessionParams (which stays
	// byte-identical to the BIP spec). nil => classic egalitarian session. When
	// non-nil it names the session leader; LeaderSecret carries the leader's fixed a0
	// (set only when Self == *Leader; nil for followers and classic).
	Leader       *thres.Identifier
	LeaderSecret []byte
}

func (p *participant) coord() string {
	if p.CoordAddr == "" {
		return CoordinatorAddr
	}
	return p.CoordAddr
}

// Run executes the two BIP rounds and finalize, returning the participant's DKG
// output and the recovery blob (eq_input ‖ certificate).
func (p *participant) Run(ctx context.Context) (thres.BIPDKGOutput, []byte, error) {
	hostseckey := p.HostSk.Serialize()

	// Fresh per-run randomness: `random` seeds the deterministic key generation,
	// `auxRand` is the BIP340 auxiliary randomness for the CertEq signature.
	random := make([]byte, 32)
	if _, err := io.ReadFull(p.Rng, random); err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}
	auxRand := make([]byte, 32)
	if _, err := io.ReadFull(p.Rng, auxRand); err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}

	// Round 1.
	pmsg1, err := p.Params.BIPParticipantStep1(hostseckey, random, p.LeaderSecret, p.Leader)
	if err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}
	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgPmsg1, Payload: pmsg1}); err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}

	cm1, err := waitFor(ctx, p.Transport.Inbox(), msgCmsg1)
	if err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}
	cmsg1 := cm1.Payload

	// Round 2: verify peers + own share, then emit the CertEq signature (pmsg2).
	pmsg2, err := p.Params.BIPParticipantStep2(hostseckey, random, cmsg1, auxRand, p.LeaderSecret, p.Leader)
	if err != nil {
		// A failed share check is attributable: request the coordinator's investigation
		// message and pin the faulty party.
		if errors.Is(err, thres.ErrInvalidSecretShare) {
			if serr := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgInvRequest}); serr != nil {
				return thres.BIPDKGOutput{}, nil, serr
			}
			inv, ierr := waitFor(ctx, p.Transport.Inbox(), msgCinv)
			if ierr != nil {
				return thres.BIPDKGOutput{}, nil, &thres.BIPFaultyCoordinatorError{Reason: "no investigation data"}
			}
			return thres.BIPDKGOutput{}, nil, p.Params.BIPParticipantInvestigate(hostseckey, cmsg1, inv.Payload)
		}
		return thres.BIPDKGOutput{}, nil, err
	}
	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgPmsg2, Payload: pmsg2}); err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}

	// Await the certificate (cmsg2) or an abort (another participant faulted).
	m, err := waitForAny(ctx, p.Transport.Inbox(), msgCmsg2, msgAbort)
	if err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}
	if m.Type == msgAbort {
		return thres.BIPDKGOutput{}, nil, ErrCeremonyAborted
	}
	out, rec, err := p.Params.BIPParticipantFinalize(hostseckey, cmsg1, m.Payload)
	if err != nil {
		return thres.BIPDKGOutput{}, nil, err
	}
	return out, rec, nil
}
