package thresholdchilldkg

import (
	"context"
	"io"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Participant runs the key-holder side of the ChillDKG protocol over a Transport.
type Participant struct {
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

func (p *Participant) coord() string {
	if p.CoordAddr == "" {
		return CoordinatorAddr
	}
	return p.CoordAddr
}

// Run executes round 1, round 2, and finalize, returning the participant's
// DKG output and the recovery data (transcript + success certificate).
func (p *Participant) Run(ctx context.Context) (thres.DKGOutput, thres.RecoveryData, error) {
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
	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgEnc2, Payload: encPayload}); err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Receive this participant's aggregated encrypted share.
	encShareMsg, err := waitFor(ctx, p.Transport.Inbox(), msgEncShare)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	encShare, err := hexToScalar(string(encShareMsg.Payload))
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Finalize: decrypt + verify share, build key packages, sign the transcript.
	out, eqInput, sig, err := thres.ParticipantFinalize(p.Params, p.Self, encShare, round1All, ephPubs, p.HostSk)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	if err := p.Transport.SendTo(ctx, p.coord(), Message{Type: msgCert, Payload: sig.Serialize()}); err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}

	// Receive the full success certificate and verify it.
	certMsg, err := waitFor(ctx, p.Transport.Inbox(), msgCertSet)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	sigs, err := unmarshalCertSet(certMsg.Payload)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	rec, err := thres.VerifyCertificate(p.Params, eqInput, sigs, round1All, ephPubs)
	if err != nil {
		return thres.DKGOutput{}, thres.RecoveryData{}, err
	}
	return out, rec, nil
}
