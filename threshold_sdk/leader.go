package thresholdsdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	core "github.com/ArkLabsHQ/threshold-magic/threshold_core"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// leaderIDValue is the leader's fixed identifier; joiners get ids above it.
const leaderIDValue = 1

// Leader is the custodial owner of one or more leader/follower threshold keys. It
// runs the gRPC relay (coordinator) AND participates, contributing each key's
// secret a0; every other party (a Follower) contributes the identity element. Each
// secret is named by a label: a0 for a label is generated once and persisted, so
// that label's aggregate public key is stable across re-DKGs as members join or are
// banned. The committee starts as just the leader and grows via the Join RPC; a
// label's DKG runs when a follower requests a reshare for it (RequestReshare) and
// the committee has at least two members.
//
// Trust model: custodial. The leader knows every group secret; followers only hold
// threshold shares of them and never learn or contribute to them.
type Leader struct {
	hostSk *secp.PrivateKey
	self   core.Identifier
	store  Store
	lis    net.Listener
	srv    *Server

	events chan membershipEvent   // join/ban/reshare events drained by Serve
	keys   chan core.BIPDKGOutput // the leader's own (re-)DKG outputs; consume via Keys()

	// authorize, when non-nil, gates every Join: a host public key it rejects is
	// refused admission even with a valid proof-of-possession.
	authorize func(hostPubkey []byte) bool

	mu        sync.Mutex
	committee map[core.Identifier]*secp.PublicKey // current members (incl. the leader)
	banned    map[string]bool                     // hex(hostpub) blocklist
	nextID    uint16                              // next identifier to assign on join
	epoch     uint64                              // monotonic re-DKG epoch (across all labels)
	groups    map[string]*groupState              // label -> last successful re-DKG result
}

// groupState is the last successful re-DKG result for one label.
type groupState struct {
	key  []byte // stable group public key (33-byte compressed)
	size int    // member count of the last successful re-DKG
	t    int    // signing threshold of the last successful re-DKG
}

// eventKind classifies a pending Serve action.
type eventKind int

const (
	evJoin    eventKind = iota // a new member joined (record it; no re-DKG yet)
	evBan                      // a member was banned (re-DKG every known label)
	evReshare                  // a follower asked to (re-)share a named label
)

// membershipEvent is a pending committee change or reshare handled by the Serve loop.
type membershipEvent struct {
	kind  eventKind
	id    core.Identifier
	pub   *secp.PublicKey // set for a join
	label string          // set for a reshare
}

// Option customizes a Leader at construction. Options are applied in order.
type Option func(*Leader)

// WithAuthorize installs an admission callback consulted on every Join, after the
// proof-of-possession check and before an identifier is assigned. Returning false
// refuses the join. Passing nil (or omitting the option) leaves the default: any
// host key with a valid proof may join.
func WithAuthorize(fn func(hostPubkey []byte) bool) Option {
	return func(l *Leader) { l.authorize = fn }
}

// NewLeader binds a gRPC listener and prepares a leader whose committee initially
// holds only itself. Followers join via the Join RPC (NewJoiningFollower) and then
// request per-label reshares. Use a ":0" port and read it back with Addr.
func NewLeader(hostSk *secp.PrivateKey, listenAddr string, store Store, opts ...Option) (*Leader, error) {
	if hostSk == nil {
		return nil, errors.New("thresholdsdk: nil host key")
	}
	if store == nil {
		return nil, errors.New("thresholdsdk: nil store")
	}
	self, err := core.IdentifierFromUint16(leaderIDValue)
	if err != nil {
		return nil, err
	}
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	srv := newDynamicServer(lis)
	srv.addSub(addr(self)) // the leader's own queue, for its loopback participant half
	l := &Leader{
		hostSk:    hostSk,
		self:      self,
		store:     store,
		lis:       lis,
		srv:       srv,
		events:    make(chan membershipEvent, 16),
		keys:      make(chan core.BIPDKGOutput, chanBuf),
		committee: map[core.Identifier]*secp.PublicKey{self: hostSk.PubKey()},
		banned:    make(map[string]bool),
		nextID:    leaderIDValue + 1,
		groups:    make(map[string]*groupState),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}
	return l, nil
}

// Addr is the resolved listen address; followers dial it.
func (l *Leader) Addr() net.Addr { return l.lis.Addr() }

// HostPubKey is the leader's host public key — followers pin it to verify the leader's signed
// commands. (Convenience for wiring tests/clients.)
func (l *Leader) HostPubKey() *secp.PublicKey { return l.hostSk.PubKey() }

// Keys delivers the leader's own output after each successful (re-)DKG — the leader
// is a full participant and holds a threshold share (out.Secshare)
func (l *Leader) Keys() <-chan core.BIPDKGOutput { return l.keys }

// GroupPubKey is the stable group public key (33-byte compressed) for a label
func (l *Leader) GroupPubKey(label string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g := l.groups[label]
	if g == nil || g.key == nil {
		return nil, errors.New("thresholdsdk: no key yet for label (needs a member to reshare)")
	}
	return g.key, nil
}

// GroupSize is the member count of label's most recent successful re-DKG (0 before any).
func (l *Leader) GroupSize(label string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if g := l.groups[label]; g != nil {
		return g.size
	}
	return 0
}

// Threshold is the signing threshold of label's most recent successful re-DKG (0 before any).
func (l *Leader) Threshold(label string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if g := l.groups[label]; g != nil {
		return g.t
	}
	return 0
}

// secretFor returns a label's a0 from the store. a0 is membership-independent, which
// keeps a label's group key stable across re-DKGs; the store owns a0's lifecycle
func (l *Leader) secretFor(label string) ([]byte, error) {
	return l.store.GetLeaderSecret(label)
}

// Close stops the relay and closes the store.
func (l *Leader) Close() error {
	l.srv.Close()
	return l.store.Close()
}

// rekeyTimeout bounds each round of a re-DKG. A member that does not contribute
// within it is evicted, and the re-DKG retries over the responsive remainder.
const rekeyTimeout = 8 * time.Second

// ErrTooFewMembers is returned when a membership change would leave fewer than two
// members (the minimum for a threshold key).
var ErrTooFewMembers = errors.New("thresholdsdk: too few members for a threshold key")

// Serve runs the leader as a long-lived daemon: it serves the relay, records joins,
// bans, and follower reshare requests, and runs a per-label
func (l *Leader) Serve(ctx context.Context) error {
	l.srv.onJoin = l.handleJoin
	l.srv.Start()
	go l.drainReshareReqs(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-l.events:
			switch ev.kind {
			case evJoin:
				l.applyJoin(ev)
			case evReshare:
				if err := l.rekey(ctx, ev.label); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return err
				}
			case evBan:
				l.notifyRemoved(ctx, ev.id)
				l.applyBan(ev)
				if err := l.rekeyAll(ctx); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return err
				}
			}
		}
	}
}

// drainReshareReqs converts follower reshare requests (relay Sends to ReshareAddr)
// into evReshare events. The requester must be a current committee member.
func (l *Leader) drainReshareReqs(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-l.srv.ReshareReqs():
			id, err := idOf(m.From)
			if err != nil {
				continue
			}
			l.mu.Lock()
			_, member := l.committee[id]
			l.mu.Unlock()
			if !member {
				continue // only admitted members may drive a reshare
			}
			select {
			case l.events <- membershipEvent{kind: evReshare, id: id, label: string(m.Payload)}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (l *Leader) applyJoin(ev membershipEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.committee[ev.id] = ev.pub
}

func (l *Leader) applyBan(ev membershipEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.committee, ev.id)
}

func (l *Leader) committeeSnapshot() map[core.Identifier]*secp.PublicKey {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[core.Identifier]*secp.PublicKey, len(l.committee))
	for id, pub := range l.committee {
		out[id] = pub
	}
	return out
}

func (l *Leader) notifyRemoved(ctx context.Context, id core.Identifier) {
	l.mu.Lock()
	epoch := l.epoch
	l.mu.Unlock()
	if signed, err := signCommand(l.hostSk, leaderCmd{Kind: cmdRemoved, Epoch: epoch, Target: addrOf(id)}); err == nil {
		_ = l.srv.SendTo(ctx, addrOf(id), Message{Type: msgRemoved, Payload: signed})
	}
	l.srv.removeSub(addrOf(id))
}

// rekeyAll re-shares every label the leader has produced a group for. Used after a
// ban so no evicted member retains a share of any secret.
func (l *Leader) rekeyAll(ctx context.Context) error {
	l.mu.Lock()
	labels := make([]string, 0, len(l.groups))
	for lbl := range l.groups {
		labels = append(labels, lbl)
	}
	l.mu.Unlock()
	for _, lbl := range labels {
		if err := l.rekey(ctx, lbl); err != nil {
			return err
		}
	}
	return nil
}

// rekey runs a re-DKG for one label, evicting non-responders and retrying until it
// succeeds over a fully-responsive committee. It is a no-op while fewer than two
// members are present (the secret stays leader-only until a follower reshares).
func (l *Leader) rekey(ctx context.Context, label string) error {
	a0, err := l.secretFor(label)
	if err != nil {
		return err
	}
	for {
		committee := l.committeeSnapshot()
		if len(committee) < 2 {
			return nil
		}
		l.mu.Lock()
		l.epoch++
		epoch := l.epoch
		l.mu.Unlock()

		out, rec, nonResp, err := l.attempt(ctx, label, a0, committee, epoch)
		if err != nil {
			return err
		}
		if len(nonResp) == 0 {
			l.mu.Lock()
			prev := l.groups[label]
			l.mu.Unlock()
			if prev != nil && prev.key != nil && !bytes.Equal(out.ThresholdPubkey, prev.key) {
				return errors.New("thresholdsdk: group key drifted across re-DKG")
			}
			if err := l.store.PutRecovery(out.ThresholdPubkey, rec); err != nil {
				return err
			}
			l.mu.Lock()
			l.groups[label] = &groupState{key: out.ThresholdPubkey, size: len(committee), t: int(MajorityPolicy(len(committee)))}
			l.mu.Unlock()
			out.Label = label
			select {
			case l.keys <- out:
			default: // observer not draining: drop (best-effort, never stall the protocol)
			}
			return nil
		}
		// Evict non-responders, then retry over the remainder.
		for _, id := range nonResp {
			l.notifyRemoved(ctx, id)
			l.mu.Lock()
			delete(l.committee, id)
			l.mu.Unlock()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// attempt runs one bounded re-DKG for label over committee at epoch, using a0 as the
// leader's secret. It returns the leader's output + recovery on full success, or the
// members that failed to contribute a round in time, for the caller to evict and retry.
func (l *Leader) attempt(ctx context.Context, label string, a0 []byte, committee map[core.Identifier]*secp.PublicKey, epoch uint64) (core.BIPDKGOutput, []byte, []core.Identifier, error) {
	t := MajorityPolicy(len(committee))
	params, err := core.NewSessionParams(t, committee)
	if err != nil {
		return core.BIPDKGOutput{}, nil, nil, err
	}
	ids := params.IDs()
	index := make(map[core.Identifier]int, len(ids))
	for i, id := range ids {
		index[id] = i
		l.srv.addSub(addrOf(id))
	}

	signed, err := signCommand(l.hostSk, rekeyCommand(label, epoch, t, l.self, committee))
	if err != nil {
		return core.BIPDKGOutput{}, nil, nil, err
	}
	if err := l.srv.Broadcast(ctx, Message{Type: msgRekey, Payload: signed}); err != nil {
		return core.BIPDKGOutput{}, nil, nil, err
	}

	// Leader's own participant half over the loopback; abandoned (pcancel) if we retry.
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	type pres struct {
		out core.BIPDKGOutput
		rec []byte
		err error
	}
	pdone := make(chan pres, 1)
	go func() {
		dp := &participant{
			Params: params, Self: l.self, HostSk: l.hostSk, Rng: rand.Reader,
			Transport: newLoopback(l.srv, l.self), Leader: &l.self, LeaderSecret: a0,
		}
		o, r, e := dp.Run(pctx)
		pdone <- pres{o, r, e}
	}()
	abandon := func() { pcancel(); <-pdone }

	// Phase 1: pmsg1.
	pmsg1, nonResp := l.collect(ctx, ids, index, msgPmsg1)
	if len(nonResp) > 0 {
		abandon()
		return core.BIPDKGOutput{}, nil, nonResp, nil
	}
	cmsg1, err := params.BIPCoordinatorStep1(pmsg1, &l.self)
	if err != nil {
		abandon()
		return core.BIPDKGOutput{}, nil, nil, err
	}
	if err := l.srv.Broadcast(ctx, Message{Type: msgCmsg1, Payload: cmsg1}); err != nil {
		abandon()
		return core.BIPDKGOutput{}, nil, nil, err
	}

	// Phase 2: pmsg2 (the CertEq signatures).
	pmsg2, nonResp2 := l.collect(ctx, ids, index, msgPmsg2)
	if len(nonResp2) > 0 {
		abandon()
		return core.BIPDKGOutput{}, nil, nonResp2, nil
	}
	if _, _, err := params.BIPCoordinatorFinalize(cmsg1, pmsg2); err != nil {
		_ = l.srv.Broadcast(ctx, Message{Type: msgAbort})
		abandon()
		return core.BIPDKGOutput{}, nil, nil, err
	}
	if err := l.srv.Broadcast(ctx, Message{Type: msgCmsg2, Payload: bytes.Join(pmsg2, nil)}); err != nil {
		abandon()
		return core.BIPDKGOutput{}, nil, nil, err
	}
	pr := <-pdone
	if pr.err != nil {
		return core.BIPDKGOutput{}, nil, nil, pr.err
	}
	pr.out.Label = label
	return pr.out, pr.rec, nil, nil
}

// collect gathers one `want` message from each member within rekeyTimeout, positioned
// by index (the leader's own arrives via the loopback). It returns the positioned
// payloads and the members that did not respond in time.
func (l *Leader) collect(ctx context.Context, ids []core.Identifier, index map[core.Identifier]int, want string) ([][]byte, []core.Identifier) {
	out := make([][]byte, len(ids))
	seen := make(map[core.Identifier]bool, len(ids))
	dctx, cancel := context.WithTimeout(ctx, rekeyTimeout)
	defer cancel()
	inbox := l.srv.Inbox()
	for len(seen) < len(ids) {
		m, err := waitForAny(dctx, inbox, want)
		if err != nil {
			break
		}
		id, err := idOf(m.From)
		if err != nil {
			continue
		}
		if _, ok := index[id]; !ok || seen[id] {
			continue
		}
		seen[id] = true
		out[index[id]] = m.Payload
	}
	var nonResp []core.Identifier
	for _, id := range ids {
		if !seen[id] {
			nonResp = append(nonResp, id)
		}
	}
	return out, nonResp
}

// handleJoin (the Server.onJoin callback) admits a new party: verify its proof,
// reject banned/duplicate keys, assign an identifier, create its queue, and enqueue
// a join event. The member receives shares once it (or another) requests a reshare.
func (l *Leader) handleJoin(hostPubkey, proof []byte) (core.Identifier, error) {
	pub, err := secp.ParsePubKey(hostPubkey)
	if err != nil {
		return core.Identifier{}, errors.New("invalid host pubkey")
	}
	if !verifyJoinProof(pub, proof) {
		return core.Identifier{}, errors.New("invalid join proof")
	}
	if l.authorize != nil && !l.authorize(hostPubkey) {
		return core.Identifier{}, errors.New("host key not authorized")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.banned[string(hostPubkey)] {
		return core.Identifier{}, errors.New("host key is banned")
	}
	for _, p := range l.committee {
		if bytes.Equal(p.SerializeCompressed(), hostPubkey) {
			return core.Identifier{}, errors.New("already a member")
		}
	}
	id := l.assignIDLocked()
	l.srv.addSub(addrOf(id))
	select {
	case l.events <- membershipEvent{kind: evJoin, id: id, pub: pub}:
		return id, nil
	default:
		return core.Identifier{}, errors.New("join queue full")
	}
}

// assignIDLocked returns the next free sequential identifier (l.mu held).
func (l *Leader) assignIDLocked() core.Identifier {
	for {
		id, err := core.IdentifierFromUint16(l.nextID)
		l.nextID++
		if err != nil {
			continue
		}
		if _, taken := l.committee[id]; taken {
			continue
		}
		return id
	}
}

// Ban blocklists a member's host key and re-shares every label over the remaining
// committee. The banned member is told to stop. Banning the leader is refused.
func (l *Leader) Ban(ctx context.Context, hostPubkey []byte) error {
	l.mu.Lock()
	l.banned[string(hostPubkey)] = true
	var target core.Identifier
	found := false
	for id, p := range l.committee {
		if bytes.Equal(p.SerializeCompressed(), hostPubkey) {
			target, found = id, true
			break
		}
	}
	l.mu.Unlock()
	if !found {
		return nil // not a current member; the blocklist still bars a future join
	}
	if target.Equal(l.self) {
		return errors.New("thresholdsdk: leader cannot ban itself")
	}
	select {
	case l.events <- membershipEvent{kind: evBan, id: target}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
