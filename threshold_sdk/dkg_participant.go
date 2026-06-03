package thresholdsdk

import (
	"context"
	"errors"
	"io"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// dkgParticipant runs the key-holder side of the ChillDKG protocol over a Transport.
type dkgParticipant struct {
	Params    thres.SessionParams
	Self      thres.Identifier
	HostSk    *secp.PrivateKey
	Secret    thres.SecretKey
	Coeffs    []secp.ModNScalar
	Rng       io.Reader
	Transport Transport
	// CoordAddr is the coordinator's transport address (defaults to CoordinatorAddr).
	CoordAddr string
}

func (p *dkgParticipant) coord() string {
	if p.CoordAddr == "" {
		return CoordinatorAddr
	}
	return p.CoordAddr
}

// Run executes round 1, round 2, and finalize, returning the participant's
// DKG output and the recovery data (transcript + success certificate).
func (p *dkgParticipant) Run(ctx context.Context) (thres.DKGOutput, thres.RecoveryData, error) {
	// Round 1: VSS commitment + PoK + ephemeral key.
	r1secret, r1pub, eph, err := thres.ParticipantStep1(p.Params, p.Self, p.Secret, p.Coeffs, p.Rng)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	r1payload, err := marshalRound1(r1pub, eph.Pub)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgRound1, Payload: r1payload}); err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Receive the coordinator's broadcast of all round-1 contributions.
	cmsg1, err := waitFor(ctx, p.Transport.Inbox(), msgCmsg1)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	round1All, ephPubs, err := unmarshalCmsg1(cmsg1.Payload)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Round 2: encrypt shares for every peer.
	peers := make(map[thres.Identifier]thres.Round1Package, len(round1All)-1)
	for id, pkg := range round1All {
		if !id.Equal(p.Self) {
			peers[id] = pkg
		}
	}
	_, enc, err := thres.ParticipantStep2(p.Params, r1secret, peers, eph, p.HostSk)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	encPayload, err := marshalEnc2(enc)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgEncRound2, Payload: encPayload}); err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Receive the broadcast of every participant's aggregated encrypted share;
	// keep them all for RecoveryData and use our own to finalize.
	encMsg, err := waitFor(ctx, p.Transport.Inbox(), msgEncShares)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	encShares, err := unmarshalEncShares(encMsg.Payload)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	encShare, ok := encShares[p.Self]
	if !ok {
		return thres.DKGOutput{}, thres.RecoveryData{}, ErrProtocol
	}

	// Finalize: decrypt + verify share, build key packages, sign the transcript.
	out, eqInput, sig, ferr := thres.ParticipantFinalize(p.Params, p.Self, encShare, round1All, ephPubs, p.HostSk)
	if ferr != nil {
		// Request the per-sender ciphertexts to attribute the fault. Sent
		// unconditionally so the coordinator's phase-3 count stays exact.
		if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgInvRequest}); err != nil {
			return thres.DKGOutput{}, thres.RecoveryData{}, err
		}
		invMsg, err := waitFor(ctx, p.Transport.Inbox(), msgInvData)
		if err != nil {
			// A coordinator that withholds investigation data is itself faulty.
			return thres.DKGOutput{}, thres.RecoveryData{}, &thres.FaultyCoordinatorError{Reason: "no investigation data"}
		}
		// Only a share mismatch is attributable; other failures are returned as-is.
		if !errors.Is(ferr, thres.ErrInvalidSecretShare) {
			return thres.DKGOutput{}, thres.RecoveryData{}, ferr
		}
		partials, err := unmarshalAuthShares(invMsg.Payload)
		if err != nil {
			return thres.DKGOutput{}, thres.RecoveryData{}, err
		}
		// Use the cmsg1-retained round1All/ephPubs (never coordinator-resupplied).
		blame := thres.InvestigateShare(p.Params, p.Self, encShare, partials, ephPubs, p.HostSk, round1All)
		return thres.DKGOutput{}, thres.RecoveryData{}, blame
	}

	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgCert, Payload: sig.Serialize()}); err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Await the success certificate or an abort (another participant faulted).
	m, err := waitForAny(ctx, p.Transport.Inbox(), msgCertSet, msgAbort)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	if m.Type == msgAbort {
		return thres.DKGOutput{}, thres.RecoveryData{}, ErrCeremonyAborted
	}
	sigs, err := unmarshalCertSet(m.Payload)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	rec, err := thres.VerifyCertificate(p.Params, eqInput, sigs, round1All, ephPubs, encShares)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	return out, rec, nil
}
