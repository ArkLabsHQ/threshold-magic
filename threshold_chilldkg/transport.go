// Package thresholdchilldkg is the transport-agnostic SDK for ChillDKG
// (encrypted PedPop + CertEq), built on thresholdcore's pure step functions. It
// adds a Transport abstraction and the Participant/Coordinator roles that run a
// full ceremony over any message channel, plus an in-memory transport (MemHub).
package thresholdchilldkg

import (
	"context"
	"sync"
)

// Message is the unit exchanged over a Transport. Addresses are hex-encoded
// participant identifiers (thresholdcore.Identifier serialized), with the
// coordinator using the reserved address CoordinatorAddr.
type Message struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to,omitempty"` // empty == broadcast
	Payload []byte `json:"payload"`
}

// CoordinatorAddr is the reserved transport address of the coordinator role.
const CoordinatorAddr = "coordinator"

// Message type tags.
const (
	msgRound1   = "round1"   // participant -> coordinator
	msgCmsg1    = "cmsg1"    // coordinator -> all (broadcast)
	msgEnc2     = "enc2"     // participant -> coordinator
	msgEncShare = "encshare" // coordinator -> participant
	msgCert     = "cert"     // participant -> coordinator
	msgCertSet  = "certset"  // coordinator -> all (broadcast)
)

// Transport is the pluggable message channel a Session drives the protocol over.
// Implementations must deliver Broadcast to every endpoint except the sender,
// and SendTo to the named recipient's inbox.
type Transport interface {
	// Broadcast delivers msg to all other endpoints.
	Broadcast(ctx context.Context, msg Message) error
	// SendTo delivers msg to a single endpoint by address.
	SendTo(ctx context.Context, to string, msg Message) error
	// Inbox returns the channel of messages addressed to this endpoint.
	Inbox() <-chan Message
}

// MemHub is an in-process Transport fabric wiring several endpoints together.
// It is intended for tests and local simulation.
type MemHub struct {
	mu      sync.RWMutex
	inboxes map[string]chan Message
}

// NewMemHub creates an empty hub.
func NewMemHub() *MemHub {
	return &MemHub{inboxes: make(map[string]chan Message)}
}

// Endpoint registers (or returns) the transport endpoint for addr.
func (h *MemHub) Endpoint(addr string) *MemTransport {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.inboxes[addr]
	if !ok {
		ch = make(chan Message, 256)
		h.inboxes[addr] = ch
	}
	return &MemTransport{hub: h, addr: addr, inbox: ch}
}

// MemTransport is one endpoint on a MemHub.
type MemTransport struct {
	hub   *MemHub
	addr  string
	inbox chan Message
}

// Broadcast implements Transport.
func (t *MemTransport) Broadcast(ctx context.Context, msg Message) error {
	msg.From = t.addr
	t.hub.mu.RLock()
	targets := make([]chan Message, 0, len(t.hub.inboxes))
	for addr, ch := range t.hub.inboxes {
		if addr != t.addr {
			targets = append(targets, ch)
		}
	}
	t.hub.mu.RUnlock()
	for _, ch := range targets {
		select {
		case ch <- msg:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// SendTo implements Transport.
func (t *MemTransport) SendTo(ctx context.Context, to string, msg Message) error {
	msg.From = t.addr
	msg.To = to
	t.hub.mu.RLock()
	ch := t.hub.inboxes[to]
	t.hub.mu.RUnlock()
	if ch == nil {
		return nil // unknown endpoint: drop (mirrors a relay with no such subscriber)
	}
	select {
	case ch <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Inbox implements Transport.
func (t *MemTransport) Inbox() <-chan Message { return t.inbox }
