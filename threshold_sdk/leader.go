package thresholdsdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// leaderIDValue is the leader's fixed identifier; joiners get ids above it.
const leaderIDValue = 1

// Leader is the custodial owner of a leader/follower threshold key. It runs the gRPC
// relay (coordinator) AND participates, contributing the secret a0; every other
// party (a Follower) contributes the identity element. a0 is generated once and
// persisted, so the aggregate public key is stable across re-DKGs as members join or
// are banned. The committee starts as just the leader and grows dynamically via the
// Join RPC; the first DKG runs once a second member joins.
//
// Trust model: custodial. The leader knows the full group secret; followers only hold
// threshold shares of it and never learn or contribute to it.
type Leader struct {
	hostSk *secp.PrivateKey
	self   core.Identifier
	store  Store
	lis    net.Listener
	srv    *Server

	a0     []byte               // loaded once in Serve
	events chan membershipEvent // join/ban events drained by Serve

	mu        sync.Mutex
	committee map[core.Identifier]*secp.PublicKey // current members (incl. the leader)
	banned    map[string]bool                     // hex(hostpub) blocklist
	nextID    uint16                              // next identifier to assign on join
	epoch     uint64                              // monotonic re-DKG epoch
	groupKey  []byte                              // stable group key once known
	groupSize int                                 // member count of the last successful re-DKG
}

// membershipEvent is a pending committee change handled by the Serve loop.
type membershipEvent struct {
	join bool
	id   core.Identifier
	pub  *secp.PublicKey // set for a join
}

// NewLeader binds a gRPC listener and prepares a leader whose committee initially
// holds only itself. Followers join via the Join RPC (NewJoiningFollower); the first DKG
// runs once the committee reaches two. Use a ":0" port and read it back with Addr.
func NewLeader(hostSk *secp.PrivateKey, listenAddr string, store Store) (*Leader, error) {
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
	return &Leader{
		hostSk:    hostSk,
		self:      self,
		store:     store,
		lis:       lis,
		srv:       srv,
		events:    make(chan membershipEvent, 16),
		committee: map[core.Identifier]*secp.PublicKey{self: hostSk.PubKey()},
		banned:    make(map[string]bool),
		nextID:    leaderIDValue + 1,
	}, nil
}

// Addr is the resolved listen address; followers dial it.
func (l *Leader) Addr() net.Addr { return l.lis.Addr() }

// Pub is the leader's host public key — followers pin it to verify the leader's signed
// commands. (Convenience for wiring tests/clients.)
func (l *Leader) Pub() *secp.PublicKey { return l.hostSk.PubKey() }

// Pubkey is the stable group public key (33-byte compressed), available after the
// first successful DKG.
func (l *Leader) Pubkey() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.groupKey == nil {
		return nil, errors.New("thresholdsdk: no key yet (needs a member to join)")
	}
	return l.groupKey, nil
}

// GroupSize is the member count of the most recent successful re-DKG (0 before any).
// It lets a caller wait for the group to reach a target size.
func (l *Leader) GroupSize() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.groupSize
}

// secret loads the leader's persisted a0, generating and persisting a fresh one on
// first use. a0 is membership-independent, which is what keeps the group key stable.
func (l *Leader) secret() ([]byte, error) {
	if a0, err := l.store.GetLeaderSecret(); err == nil {
		return a0, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	k, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	a0 := k.Serialize()
	if err := l.store.PutLeaderSecret(a0); err != nil {
		return nil, err
	}
	return a0, nil
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

// Serve runs the leader as a long-lived daemon: it serves the relay, runs the
// initial DKG over the seed committee, then re-DKGs on every membership change —
// joins (via the Join RPC) and bans (via Ban) — reusing a0 so the group public key
// never moves. It blocks until ctx is done.
func (l *Leader) Serve(ctx context.Context) error {
	a0, err := l.secret()
	if err != nil {
		return err
	}
	l.a0 = a0
	l.srv.onJoin = l.handleJoin
	l.srv.Start()

	// No DKG until a second member joins; each join/ban then drives a re-DKG.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-l.events:
			if !ev.join { // ban: tell the member to stop and drop it before re-DKG
				l.notifyRemoved(ctx, ev.id)
			}
			l.applyEvent(ev)
			if err := l.rekey(ctx); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
		}
	}
}

func (l *Leader) applyEvent(ev membershipEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.join {
		l.committee[ev.id] = ev.pub
	} else {
		delete(l.committee, ev.id)
	}
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

// rekey runs a re-DKG, evicting non-responders and retrying until it succeeds over a
// fully-responsive committee (or too few members remain).
func (l *Leader) rekey(ctx context.Context) error {
	for {
		committee := l.committeeSnapshot()
		if len(committee) < 2 {
			return ErrTooFewMembers
		}
		l.mu.Lock()
		l.epoch++
		epoch := l.epoch
		l.mu.Unlock()

		out, rec, nonResp, err := l.attempt(ctx, committee, epoch)
		if err != nil {
			return err
		}
		if len(nonResp) == 0 {
			if l.groupKey != nil && !bytes.Equal(out.ThresholdPubkey, l.groupKey) {
				return errors.New("thresholdsdk: group key drifted across re-DKG")
			}
			if err := l.store.PutRecovery(out.ThresholdPubkey, rec); err != nil {
				return err
			}
			l.mu.Lock()
			l.groupKey = out.ThresholdPubkey
			l.groupSize = len(committee)
			l.mu.Unlock()
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

// attempt runs one bounded re-DKG over committee at epoch. It returns the leader's
// output + recovery on full success, or the members that failed to contribute round
// 1 (resp. round 2) in time, for the caller to evict and retry.
func (l *Leader) attempt(ctx context.Context, committee map[core.Identifier]*secp.PublicKey, epoch uint64) (core.BIPDKGOutput, []byte, []core.Identifier, error) {
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

	signed, err := signCommand(l.hostSk, rekeyCommand(epoch, t, l.self, committee))
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
			Transport: newLoopback(l.srv, l.self), Leader: &l.self, LeaderSecret: l.a0,
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
// a join event for the Serve loop to re-DKG.
func (l *Leader) handleJoin(hostPubkey, proof []byte) (core.Identifier, error) {
	pub, err := secp.ParsePubKey(hostPubkey)
	if err != nil {
		return core.Identifier{}, errors.New("invalid host pubkey")
	}
	if !verifyJoinProof(pub, proof) {
		return core.Identifier{}, errors.New("invalid join proof")
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
	case l.events <- membershipEvent{join: true, id: id, pub: pub}:
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

// Ban blocklists a member's host key and triggers a re-DKG over the remaining
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
	case l.events <- membershipEvent{join: false, id: target}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
