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

// Run collects round-1 contributions, broadcasts them, aggregates the encrypted
// shares, distributes each participant's aggregate, then collects and broadcasts
// the success certificate.
func (c *Coordinator) Run(ctx context.Context) error {
	n := int(c.Params.N)
	inbox := c.Transport.Inbox()

	// Collect N round-1 contributions.
	round1 := make(map[thres.Identifier]thres.Round1Package, n)
	ephPubs := make(map[thres.Identifier]*secp.PublicKey, n)
	for len(round1) < n {
		m, err := waitFor(ctx, inbox, msgRound1)
		if err != nil {
			return err
		}
		id, err := idOf(m.From)
		if err != nil {
			return err
		}
		pkg, ephPub, err := unmarshalRound1(m.Payload)
		if err != nil {
			return err
		}
		round1[id] = pkg
		ephPubs[id] = ephPub
	}
	if err := thres.CoordinatorStep1(c.Params, round1); err != nil {
		return err
	}
	cmsg1, err := marshalCmsg1(round1, ephPubs)
	if err != nil {
		return err
	}
	if err := c.Transport.Broadcast(ctx, Message{Type: msgCmsg1, Payload: cmsg1}); err != nil {
		return err
	}

	// Collect N encrypted round-2 messages, then aggregate per recipient.
	perSender := make(map[thres.Identifier]thres.EncRound2, n)
	for len(perSender) < n {
		m, err := waitFor(ctx, inbox, msgEnc2)
		if err != nil {
			return err
		}
		id, err := idOf(m.From)
		if err != nil {
			return err
		}
		enc, err := unmarshalEnc2(m.Payload)
		if err != nil {
			return err
		}
		perSender[id] = enc
	}
	encShares, err := thres.CoordinatorFinalize(perSender, c.Params.IDs())
	if err != nil {
		return err
	}
	for id, share := range encShares {
		if err := c.Transport.SendTo(ctx, addrOf(id), Message{Type: msgEncShare, Payload: []byte(scalarToHex(share))}); err != nil {
			return err
		}
	}

	// Collect N certificate signatures and broadcast the success certificate.
	sigs := make(map[thres.Identifier]*schnorr.Signature, n)
	for len(sigs) < n {
		m, err := waitFor(ctx, inbox, msgCert)
		if err != nil {
			return err
		}
		id, err := idOf(m.From)
		if err != nil {
			return err
		}
		sig, err := schnorr.ParseSignature(m.Payload)
		if err != nil {
			return err
		}
		sigs[id] = sig
	}
	certSet, err := marshalCertSet(sigs)
	if err != nil {
		return err
	}
	return c.Transport.Broadcast(ctx, Message{Type: msgCertSet, Payload: certSet})
}
