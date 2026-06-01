package thresholdchilldkg

import (
	"context"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

// Coordinator runs the untrusted aggregator side of the ChillDKG protocol. It
// relays and aggregates messages but never learns any secret.
type Coordinator struct {
	Params    thres.SessionParams
	Transport Transport
}

// collectFromAll invokes handle once for each of the N participants, counting
// distinct authenticated senders (non-participants ignored, first message wins)
// so a flooding participant cannot displace another's slot.
func (c *Coordinator) collectFromAll(ctx context.Context, handle func(id thres.Identifier, m Message) error, types ...string) error {
	inbox := c.Transport.Inbox()
	seen := make(map[thres.Identifier]bool, c.Params.N)
	for len(seen) < int(c.Params.N) {
		m, err := waitForAny(ctx, inbox, types...)
		if err != nil {
			return err
		}
		id, err := idOf(m.From)
		if err != nil {
			continue // unparseable sender address: ignore
		}
		if _, ok := c.Params.HostPubs[id]; !ok {
			continue // not a session participant: ignore
		}
		if seen[id] {
			continue // duplicate from this sender: first message wins
		}
		seen[id] = true
		if err := handle(id, m); err != nil {
			return err
		}
	}
	return nil
}

// Run drives the coordinator side: collect round 1, broadcast it, aggregate and
// broadcast the encrypted shares, then collect the certificate (or abort on an
// investigation request). On success it returns the canonical RecoveryData blob —
// identical to every participant's — so the coordinator can serve it later.
func (c *Coordinator) Run(ctx context.Context) (thres.RecoveryData, error) {
	n := int(c.Params.N)

	// Phase 1: collect round-1 contributions, then broadcast them to everyone.
	round1 := make(map[thres.Identifier]thres.Round1Package, n)
	ephPubs := make(map[thres.Identifier]*secp.PublicKey, n)
	if err := c.collectFromAll(ctx, func(id thres.Identifier, m Message) error {
		pkg, ephPub, err := unmarshalRound1(m.Payload)
		if err != nil {
			return err
		}
		round1[id] = pkg
		ephPubs[id] = ephPub
		return nil
	}, msgRound1); err != nil {
		return thres.RecoveryData{}, err
	}
	if err := thres.CoordinatorStep1(c.Params, round1); err != nil {
		return thres.RecoveryData{}, err
	}
	cmsg1, err := marshalCmsg1(round1, ephPubs)
	if err != nil {
		return thres.RecoveryData{}, err
	}
	if err := c.Transport.Broadcast(ctx, Message{Type: msgCmsg1, Payload: cmsg1}); err != nil {
		return thres.RecoveryData{}, err
	}

	// Phase 2: collect the encrypted round-2 messages, aggregate per recipient,
	// and broadcast every aggregate.
	perSender := make(map[thres.Identifier]thres.EncRound2, n)
	if err := c.collectFromAll(ctx, func(id thres.Identifier, m Message) error {
		enc, err := unmarshalEnc2(m.Payload)
		if err != nil {
			return err
		}
		perSender[id] = enc
		return nil
	}, msgEncRound2); err != nil {
		return thres.RecoveryData{}, err
	}
	ids := c.Params.IDs()
	encShares, err := thres.CoordinatorFinalize(perSender, ids)
	if err != nil {
		return thres.RecoveryData{}, err
	}
	// Broadcast all aggregated shares (each is masked from non-recipients) so every
	// participant can both finalize its own and retain the full set for RecoveryData.
	encPayload, err := marshalEncShares(encShares)
	if err != nil {
		return thres.RecoveryData{}, err
	}
	if err := c.Transport.Broadcast(ctx, Message{Type: msgEncShares, Payload: encPayload}); err != nil {
		return thres.RecoveryData{}, err
	}

	// Phase 3: each participant sends exactly one of msgCert or msgInvRequest.
	// Ordering is load-bearing: msgInvData is sent inside the handler and msgAbort
	// only after, so a failing participant dequeues its data before the abort.
	sigs := make(map[thres.Identifier]*schnorr.Signature, n)
	aborted := false
	if err := c.collectFromAll(ctx, func(id thres.Identifier, m Message) error {
		switch m.Type {
		case msgCert:
			sig, err := schnorr.ParseSignature(m.Payload)
			if err != nil {
				return err
			}
			sigs[id] = sig
		case msgInvRequest:
			partials, err := thres.PartialCiphertextsFor(perSender, id, ids)
			if err != nil {
				return err
			}
			payload, err := marshalAuthShares(partials)
			if err != nil {
				return err
			}
			if err := c.Transport.SendTo(ctx, addrOf(id), Message{Type: msgInvData, Payload: payload}); err != nil {
				return err
			}
			aborted = true
		}
		return nil
	}, msgCert, msgInvRequest); err != nil {
		return thres.RecoveryData{}, err
	}

	if aborted {
		if err := c.Transport.Broadcast(ctx, Message{Type: msgAbort}); err != nil {
			return thres.RecoveryData{}, err
		}
		return thres.RecoveryData{}, ErrCeremonyAborted
	}

	// Assemble the recovery blob and confirm the certificate is valid before
	// broadcasting it; the coordinator then holds the same canonical blob to serve.
	rd := thres.RecoveryData{
		Params:      c.Params,
		Round1:      round1,
		EphPubs:     ephPubs,
		EncShares:   encShares,
		Certificate: sigs,
	}
	if err := rd.Verify(); err != nil {
		_ = c.Transport.Broadcast(ctx, Message{Type: msgAbort})
		return thres.RecoveryData{}, err
	}

	certSet, err := marshalCertSet(sigs)
	if err != nil {
		return thres.RecoveryData{}, err
	}
	if err := c.Transport.Broadcast(ctx, Message{Type: msgCertSet, Payload: certSet}); err != nil {
		return thres.RecoveryData{}, err
	}
	return rd, nil
}
