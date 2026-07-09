package thresholdsdk

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	core "github.com/ArkLabsHQ/threshold-magic/threshold_core"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrRemoved is returned by Follower.Serve when the leader evicts this follower.
var ErrRemoved = errors.New("thresholdsdk: removed from the group")

// Follower is a non-custodial member of a leader/follower threshold key. It
// contributes the identity element (no secret) and holds a threshold share of the
// leader's key. It joins the leader's relay and participates in every re-DKG the
// leader commands until evicted (see Serve).
type Follower struct {
	hostSk    *secp.PrivateKey
	leaderPub *secp.PublicKey // pinned leader host key (verifies signed commands)
	coordAddr string
	store     Store
	keys      chan core.BIPDKGOutput // (re-)DKG outputs; consume via Keys()

	// Set once Serve has joined, so RequestReshare can address the leader.
	mu         sync.Mutex
	client     *Client
	self       core.Identifier
	joined     chan struct{} // closed once joined
	joinedOnce sync.Once
}

// NewJoiningFollower builds a follower that joins a leader's session dynamically: it
// knows the relay address and the leader's host key (pinned to verify the leader's
// signed rekey/removed commands). Run it as a long-lived daemon with Serve.
func NewJoiningFollower(hostSk *secp.PrivateKey, coordAddr string, leaderPub *secp.PublicKey, store Store) (*Follower, error) {
	if hostSk == nil || leaderPub == nil {
		return nil, errors.New("thresholdsdk: nil host key or leader key")
	}
	if store == nil {
		return nil, errors.New("thresholdsdk: nil store")
	}
	return &Follower{
		hostSk:    hostSk,
		leaderPub: leaderPub,
		coordAddr: coordAddr,
		store:     store,
		keys:      make(chan core.BIPDKGOutput, chanBuf),
		joined:    make(chan struct{}),
	}, nil
}

// RequestReshare asks the leader to (re-)run the DKG for the named secret, so this
// follower receives its share of it (delivered on Keys() with Label == label). It
// blocks until the follower has joined (or ctx is done).
func (f *Follower) RequestReshare(ctx context.Context, label string) error {
	select {
	case <-f.joined:
	case <-ctx.Done():
		return ctx.Err()
	}
	f.mu.Lock()
	client := f.client
	f.mu.Unlock()
	if client == nil {
		return errors.New("thresholdsdk: follower not joined")
	}
	return client.SendTo(ctx, ReshareAddr, Message{Type: msgReshareReq, Payload: []byte(label)})
}

// Keys delivers this follower's output after each (re-)DKG. Sends are best-effort:
// drained promptly or dropped (never stalls the protocol). Never closed.
func (f *Follower) Keys() <-chan core.BIPDKGOutput { return f.keys }

// Serve runs the follower as a long-lived daemon. It joins the leader, then over a
// single Subscribe stream demultiplexes the leader's signed commands: each rekey
// (verified against the pinned leader key, with a monotonic epoch) starts a fresh
// ceremony — superseding any in-flight one — and the resulting share is persisted; a
// removed command (or ctx cancellation) ends the loop. It blocks until then.
func (f *Follower) Serve(ctx context.Context) error {
	proof, err := signJoinProof(f.hostSk)
	if err != nil {
		return err
	}
	client, err := NewClient(f.coordAddr, core.Identifier{})
	if err != nil {
		return err
	}
	defer client.Close()
	self, err := client.Join(ctx, f.hostSk.PubKey().SerializeCompressed(), proof)
	if err != nil {
		return err
	}
	if err := client.Start(ctx); err != nil {
		return err
	}

	f.mu.Lock()
	f.client = client
	f.self = self
	f.mu.Unlock()
	f.joinedOnce.Do(func() { close(f.joined) })

	selfAddr := addrOf(self)
	var (
		curEpoch uint64
		cerm     *followerCeremony
	)
	stop := func() {
		if cerm != nil {
			cerm.cancel()
			cerm = nil
		}
	}
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m, ok := <-client.Inbox():
			if !ok {
				return ErrProtocol
			}
			switch m.Type {
			case msgRemoved:
				if cmd, err := verifyCommand(m.Payload, f.leaderPub); err == nil &&
					cmd.Kind == cmdRemoved && cmd.Target == selfAddr {
					return ErrRemoved
				}
			case msgRekey:
				cmd, err := verifyCommand(m.Payload, f.leaderPub)
				if err != nil || cmd.Kind != cmdRekey || cmd.Epoch <= curEpoch {
					continue // bad signature, replay, or stale epoch
				}
				if _, ok := cmd.Members[selfAddr]; !ok {
					continue // a reshare for a group this follower is not part of
				}
				curEpoch = cmd.Epoch
				stop() // abandon any in-flight ceremony for an older epoch
				cerm = f.startCeremony(ctx, self, cmd, client)
			case msgCmsg1, msgCmsg2, msgCinv, msgAbort:
				if cerm != nil {
					cerm.feed(m)
				}
			}
		}
	}
}

// followerCeremony is one in-flight ceremony: a buffered inbox fed by the Serve loop
// and a cancel that supersedes it when a newer rekey arrives.
type followerCeremony struct {
	inbox  chan Message
	cancel context.CancelFunc
}

func (c *followerCeremony) feed(m Message) {
	select {
	case c.inbox <- m:
	default: // ceremony cancelled or buffer full: drop (a newer epoch supersedes)
	}
}

// startCeremony runs one follower ceremony for the rekey command in a goroutine,
// feeding it via a ceremonyTransport and persisting its output on success.
func (f *Follower) startCeremony(ctx context.Context, self core.Identifier, cmd leaderCmd, client *Client) *followerCeremony {
	params, leader, err := cmd.session()
	if err != nil {
		return nil
	}
	cctx, cancel := context.WithCancel(ctx)
	cerm := &followerCeremony{inbox: make(chan Message, chanBuf), cancel: cancel}
	tr := &ceremonyTransport{send: client, inbox: cerm.inbox}
	go func() {
		dp := &participant{
			Params:    params,
			Self:      self,
			HostSk:    f.hostSk,
			Rng:       rand.Reader,
			Transport: tr,
			Leader:    &leader,
			// LeaderSecret nil: a follower contributes the identity element.
		}
		out, rec, err := dp.Run(cctx)
		if err == nil {
			out.Label = cmd.Label
			_ = f.store.PutRecovery(out.ThresholdPubkey, rec)
			select {
			case f.keys <- out:
			default: // observer not draining: drop (best-effort, never stall the protocol)
			}
		}
	}()
	return cerm
}

// Close closes the injected store.
func (f *Follower) Close() error { return f.store.Close() }

// ceremonyTransport adapts the demux loop to a participant driver: Inbox() is the
// per-ceremony channel the loop feeds; SendTo goes to the coordinator over the shared
// client.
type ceremonyTransport struct {
	send  Transport
	inbox chan Message
}

var _ Transport = (*ceremonyTransport)(nil)

func (t *ceremonyTransport) Inbox() <-chan Message { return t.inbox }
func (t *ceremonyTransport) SendTo(ctx context.Context, to string, msg Message) error {
	return t.send.SendTo(ctx, to, msg)
}
func (t *ceremonyTransport) Broadcast(ctx context.Context, msg Message) error { return nil }
