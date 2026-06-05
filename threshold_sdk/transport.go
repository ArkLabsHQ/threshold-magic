// Package thresholdsdk is the embeddable leader/follower threshold-DKG SDK. A Leader
// (the custodial owner of the key) runs a BIP ChillDKG ceremony as both coordinator
// and participant; Followers join dynamically and contribute the identity element.
// Membership changes (join/ban) trigger a re-DKG that reuses the leader's secret, so
// the group public key never moves. Messages flow over gRPC (the Server/Client
// transport); recovery data is persisted via a Store.
package thresholdsdk

import "context"

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

// Message type tags for the BIP ChillDKG two-round flow (byte-blob payloads).
const (
	msgPmsg1 = "pmsg1" // participant -> coordinator: round-1 message
	msgCmsg1 = "cmsg1" // coordinator -> all (broadcast): aggregated round 1
	msgPmsg2 = "pmsg2" // participant -> coordinator: CertEq signature
	msgCmsg2 = "cmsg2" // coordinator -> all (broadcast): the certificate

	// Blame / investigation (abort path).
	msgInvRequest = "invreq" // participant -> coordinator (share check failed)
	msgCinv       = "cinv"   // coordinator -> participant (its investigation message)
	msgAbort      = "abort"  // coordinator -> all (broadcast): ceremony aborted

	// Dynamic membership (leader/follower sessions): signed leader commands.
	msgRekey   = "rekey"   // leader -> all: (re-)run the DKG over a committee
	msgRemoved = "removed" // leader -> a member: you have been evicted
)

// Transport is the pluggable message channel the protocol is driven over.
// Implementations must deliver Broadcast to every endpoint except the sender, and
// SendTo to the named recipient's inbox.
type Transport interface {
	// Broadcast delivers msg to all other endpoints.
	Broadcast(ctx context.Context, msg Message) error
	// SendTo delivers msg to a single endpoint by address.
	SendTo(ctx context.Context, to string, msg Message) error
	// Inbox returns the channel of messages addressed to this endpoint.
	Inbox() <-chan Message
}
