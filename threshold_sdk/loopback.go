package thresholdsdk

import (
	"context"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
)

// loopbackTransport is the leader's participant-side Transport. A leader runs the
// gRPC Server (the coordinator) AND participates; instead of dialing itself, its
// participant half talks to the Server's queues in-process:
//   - SendTo(CoordinatorAddr, …) pushes straight onto the Server's coordinator inbox;
//   - Inbox() reads the leader's own per-participant queue — the same one the Server's
//     Broadcast/SendTo write to — so broadcasts (cmsg1, cmsg2) and unicasts (cinv)
//     reach the leader exactly as they reach a remote follower.
//
// It stamps From with the leader's address so the coordinator's collectFromAll
// attributes the message to the leader, identically to a gRPC sender.
type loopbackTransport struct {
	srv      *Server
	selfAddr string
	inbox    chan Message // the leader's own queue (captured under lock at construction)
}

var _ Transport = (*loopbackTransport)(nil)

func newLoopback(srv *Server, leader thres.Identifier) *loopbackTransport {
	a := addr(leader)
	return &loopbackTransport{srv: srv, selfAddr: a, inbox: srv.addSub(a)}
}

func (l *loopbackTransport) Inbox() <-chan Message { return l.inbox }

func (l *loopbackTransport) SendTo(ctx context.Context, to string, msg Message) error {
	msg.From = l.selfAddr
	msg.To = to
	ch := l.srv.inbox
	if to != CoordinatorAddr {
		var ok bool
		if ch, ok = l.srv.sub(to); !ok {
			return nil // unknown recipient dropped, mirroring Server.SendTo
		}
	}
	select {
	case ch <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Broadcast is never used by the participant half.
func (l *loopbackTransport) Broadcast(ctx context.Context, msg Message) error { return nil }
