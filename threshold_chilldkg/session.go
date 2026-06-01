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

// ErrCeremonyAborted is returned to a participant whose own shares were valid but
// the ceremony aborted because another participant could not finalize. The
// failing participant instead gets a typed Faulty{Participant,Coordinator}Error.
var ErrCeremonyAborted = errors.New("chilldkg ceremony aborted")

// waitFor reads the inbox until a message of the wanted type arrives (messages
// of other types are consumed in FIFO order by the strictly sequential protocol)
// or the context is cancelled.
func waitFor(ctx context.Context, inbox <-chan Message, want string) (Message, error) {
	return waitForAny(ctx, inbox, want)
}

// waitForAny reads the inbox until a message whose type is one of want arrives,
// or the context is cancelled.
func waitForAny(ctx context.Context, inbox <-chan Message, want ...string) (Message, error) {
	for {
		select {
		case <-ctx.Done():
			return Message{}, ctx.Err()
		case m, ok := <-inbox:
			if !ok {
				return Message{}, ErrProtocol
			}
			for _, w := range want {
				if m.Type == w {
					return m, nil
				}
			}
		}
	}
}
