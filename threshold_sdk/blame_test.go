package thresholdsdk

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fnTransport decorates a Transport so a test can rewrite/drop outbound messages
// (onSendTo) or send dupN extra copies of dupType messages (Byzantine flooding).
type fnTransport struct {
	inner    Transport
	onSendTo func(to string, msg Message) (Message, bool)
	dupType  string
	dupN     int
}

func (f *fnTransport) Broadcast(ctx context.Context, msg Message) error {
	return f.inner.Broadcast(ctx, msg)
}

func (f *fnTransport) SendTo(ctx context.Context, to string, msg Message) error {
	if f.onSendTo != nil {
		m, forward := f.onSendTo(to, msg)
		if !forward {
			return nil
		}
		msg = m
	}
	if err := f.inner.SendTo(ctx, to, msg); err != nil {
		return err
	}
	if f.dupType != "" && msg.Type == f.dupType {
		for i := 0; i < f.dupN; i++ {
			if err := f.inner.SendTo(ctx, to, msg); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *fnTransport) Inbox() <-chan Message { return f.inner.Inbox() }

// corruptEnc2To alters a sender's round-2 ciphertext to victim while keeping its
// now-stale signature — modelling a relay that tampers with a share it can't re-sign.
func corruptEnc2To(victim thres.Identifier) func(string, Message) (Message, bool) {
	return func(to string, msg Message) (Message, bool) {
		if msg.Type != msgEncRound2 {
			return msg, true
		}
		enc, err := unmarshalEnc2(msg.Payload)
		if err != nil {
			return msg, true
		}
		sh, ok := enc.Shares[victim]
		if !ok {
			return msg, true
		}
		var one secp.ModNScalar
		one.SetInt(1)
		sh.Ciphertext.Add(&one)
		enc.Shares[victim] = sh
		payload, err := marshalEnc2(enc)
		if err != nil {
			return msg, true
		}
		msg.Payload = payload
		return msg, true
	}
}

type sessionFixture struct {
	params  thres.SessionParams
	ids     []thres.Identifier
	hostSks map[thres.Identifier]*secp.PrivateKey
	secrets map[thres.Identifier]thres.SecretKey
	coeffs  map[thres.Identifier][]secp.ModNScalar
	hub     *MemHub
}

func newSessionFixture(t *testing.T, min, max uint16) sessionFixture {
	t.Helper()
	f := sessionFixture{
		hostSks: make(map[thres.Identifier]*secp.PrivateKey, max),
		secrets: make(map[thres.Identifier]thres.SecretKey, max),
		coeffs:  make(map[thres.Identifier][]secp.ModNScalar, max),
		hub:     NewMemHub(),
	}
	hostPubs := make(map[thres.Identifier]*secp.PublicKey, max)
	for i := uint16(1); i <= max; i++ {
		id, err := thres.IdentifierFromUint16(i)
		require.NoError(t, err)
		sk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		sec, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		cs, err := thres.GenerateCoefficients(min)
		require.NoError(t, err)

		f.ids = append(f.ids, id)
		f.hostSks[id] = sk
		hostPubs[id] = sk.PubKey()
		f.secrets[id] = thres.SecretKey{Scalar: sec.Key}
		f.coeffs[id] = cs
	}
	params, err := thres.NewSessionParams(min, hostPubs)
	require.NoError(t, err)
	f.params = params
	return f
}

func (f sessionFixture) participant(id thres.Identifier, tr Transport) *dkgParticipant {
	return &dkgParticipant{
		Params:    f.params,
		Self:      id,
		HostSk:    f.hostSks[id],
		Secret:    f.secrets[id],
		Coeffs:    f.coeffs[id],
		Rng:       rand.Reader,
		Transport: tr,
	}
}

type blamePartResult struct {
	id  thres.Identifier
	out thres.DKGOutput
	rec thres.RecoveryData
	err error
}

// TestSessionBlamesCoordinatorOnShareTamper is the end-to-end demonstration that
// a relaying coordinator cannot alter a share and frame an honest sender: the
// round-2 signature it cannot forge makes the victim blame the coordinator.
func TestSessionBlamesCoordinatorOnShareTamper(t *testing.T) {
	f := newSessionFixture(t, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tamperedSender := f.ids[0] // honest, but its ciphertext is altered in transit
	victim := f.ids[1]

	// Endpoints must exist before anyone broadcasts.
	coordEp := f.hub.Endpoint(CoordinatorAddr)
	for _, id := range f.ids {
		f.hub.Endpoint(addrOf(id))
	}

	coord := &dkgCoordinator{Params: f.params, Transport: coordEp}
	parts := make([]*dkgParticipant, 0, len(f.ids))
	for _, id := range f.ids {
		base := f.hub.Endpoint(addrOf(id))
		var tr Transport = base
		if id.Equal(tamperedSender) {
			tr = &fnTransport{inner: base, onSendTo: corruptEnc2To(victim)}
		}
		parts = append(parts, f.participant(id, tr))
	}

	coordErr := make(chan error, 1)
	go func() { _, cerr := coord.Run(ctx); coordErr <- cerr }()
	ch := make(chan blamePartResult, len(parts))
	for _, p := range parts {
		p := p
		go func() {
			out, rec, err := p.Run(ctx)
			ch <- blamePartResult{p.Self, out, rec, err}
		}()
	}

	results := make(map[thres.Identifier]blamePartResult, len(parts))
	for range parts {
		r := <-ch
		results[r.id] = r
	}
	assert.ErrorIs(t, <-coordErr, ErrCeremonyAborted, "coordinator aborts")

	// The victim blames the coordinator, NOT the honest sender whose share was altered.
	var fc *thres.FaultyCoordinatorError
	require.Truef(t, errors.As(results[victim].err, &fc), "victim err: %v", results[victim].err)
	var fp *thres.FaultyParticipantError
	assert.Falsef(t, errors.As(results[victim].err, &fp), "honest sender must not be framed")

	// Everyone else aborts cleanly.
	for _, id := range f.ids {
		if id.Equal(victim) {
			continue
		}
		assert.ErrorIs(t, results[id].err, ErrCeremonyAborted)
	}
}

func TestSessionCoordinatorWithholdsInvData(t *testing.T) {
	f := newSessionFixture(t, 2, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	culprit := f.ids[0]
	victim := f.ids[1]

	coordBase := f.hub.Endpoint(CoordinatorAddr)
	for _, id := range f.ids {
		f.hub.Endpoint(addrOf(id))
	}

	// dkgCoordinator drops the investigation data it should send the victim.
	coordTr := &fnTransport{inner: coordBase, onSendTo: func(to string, msg Message) (Message, bool) {
		return msg, msg.Type != msgInvData
	}}
	coord := &dkgCoordinator{Params: f.params, Transport: coordTr}

	parts := make([]*dkgParticipant, 0, len(f.ids))
	for _, id := range f.ids {
		base := f.hub.Endpoint(addrOf(id))
		var tr Transport = base
		if id.Equal(culprit) {
			tr = &fnTransport{inner: base, onSendTo: corruptEnc2To(victim)}
		}
		parts = append(parts, f.participant(id, tr))
	}

	coordErr := make(chan error, 1)
	go func() { _, cerr := coord.Run(ctx); coordErr <- cerr }()
	ch := make(chan blamePartResult, len(parts))
	for _, p := range parts {
		p := p
		go func() {
			out, rec, err := p.Run(ctx)
			ch <- blamePartResult{p.Self, out, rec, err}
		}()
	}

	// dkgCoordinator returns after broadcasting abort; the victim is then stuck
	// waiting for investigation data that was dropped, so cancel to release it.
	assert.ErrorIs(t, <-coordErr, ErrCeremonyAborted)
	cancel()

	results := make(map[thres.Identifier]blamePartResult, len(parts))
	for range parts {
		r := <-ch
		results[r.id] = r
	}

	// A coordinator that withholds investigation data is itself blamed.
	var fc *thres.FaultyCoordinatorError
	assert.Truef(t, errors.As(results[victim].err, &fc), "victim err: %v", results[victim].err)
	for _, id := range f.ids {
		if id.Equal(victim) {
			continue
		}
		assert.ErrorIs(t, results[id].err, ErrCeremonyAborted)
	}
}

func TestCoordinatorDedupsDuplicatePhase3(t *testing.T) {
	f := newSessionFixture(t, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	flooder := f.ids[0]

	coordEp := f.hub.Endpoint(CoordinatorAddr)
	for _, id := range f.ids {
		f.hub.Endpoint(addrOf(id))
	}

	coord := &dkgCoordinator{Params: f.params, Transport: coordEp}
	parts := make([]*dkgParticipant, 0, len(f.ids))
	for _, id := range f.ids {
		base := f.hub.Endpoint(addrOf(id))
		var tr Transport = base
		if id.Equal(flooder) {
			// Flood extra certificates; the coordinator must count distinct senders.
			tr = &fnTransport{inner: base, dupType: msgCert, dupN: 3}
		}
		parts = append(parts, f.participant(id, tr))
	}

	coordErr := make(chan error, 1)
	go func() { _, cerr := coord.Run(ctx); coordErr <- cerr }()
	ch := make(chan blamePartResult, len(parts))
	for _, p := range parts {
		p := p
		go func() {
			out, rec, err := p.Run(ctx)
			ch <- blamePartResult{p.Self, out, rec, err}
		}()
	}

	results := make(map[thres.Identifier]blamePartResult, len(parts))
	for range parts {
		r := <-ch
		results[r.id] = r
	}
	require.NoError(t, <-coordErr, "coordinator should complete despite duplicate certs")

	// Every participant completes successfully and agrees on the group key.
	var ref thres.VerifyingKey
	for i, id := range f.ids {
		require.NoErrorf(t, results[id].err, "participant %v", id)
		vk := results[id].out.Key.VerifyingKey
		if i == 0 {
			ref = vk
			continue
		}
		assert.True(t, ref.E.EquivalentNonConst(&vk.E))
	}
}
