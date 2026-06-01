package thresholdchilldkg

import (
	"context"
	"errors"
)

// A ChillDKG session has two roles, each driven over a Transport:
//   - Participant (one per key holder) — see participant.go
//   - Coordinator (one untrusted aggregator) — see coordinator.go
//
// Both build on the pure step functions in thresholdcore and share the small
// receive helper below.

// ErrProtocol indicates a malformed or out-of-order protocol message.
var ErrProtocol = errors.New("chilldkg protocol error")

// waitFor reads the inbox until a message of the wanted type arrives (messages
// of other types are consumed in FIFO order by the strictly sequential protocol)
// or the context is cancelled.
func waitFor(ctx context.Context, inbox <-chan Message, want string) (Message, error) {
	for {
		select {
		case <-ctx.Done():
			return Message{}, ctx.Err()
		case m, ok := <-inbox:
			if !ok {
				return Message{}, ErrProtocol
			}
			if m.Type == want {
				return m, nil
			}
		}
	}
}
