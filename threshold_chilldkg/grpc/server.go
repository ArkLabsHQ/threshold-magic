// Package chillgrpc is an insecure gRPC transport for the thresholdchilldkg SDK.
// The coordinator runs Server (a gRPC relay); each participant runs Client. It
// implements thresholdchilldkg.Transport with the same semantics as MemHub.
package chillgrpc

import (
	"context"
	"encoding/hex"
	"net"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	chill "thresholdchilldkg"
	"thresholdchilldkggrpc/relaypb"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative relaypb/relay.proto

// chanBuf mirrors MemHub's per-endpoint buffer size.
const chanBuf = 256

// addr is the transport address of an identifier — identical to the parent's
// addrOf (hex of the serialized scalar).
func addr(id thres.Identifier) string { return hex.EncodeToString(id.Serialize()) }

func toEnvelope(m chill.Message) *relaypb.Envelope {
	return &relaypb.Envelope{Type: m.Type, From: m.From, To: m.To, Payload: m.Payload}
}

func fromEnvelope(e *relaypb.Envelope) chill.Message {
	return chill.Message{Type: e.Type, From: e.From, To: e.To, Payload: e.Payload}
}

// Server is the coordinator-side transport: a gRPC relay that also satisfies
// thresholdchilldkg.Transport. Participants Send to it (routed to the coordinator
// inbox) and Subscribe to receive the messages addressed to them.
type Server struct {
	relaypb.UnimplementedRelayServer

	inbox chan chill.Message            // messages addressed to the coordinator
	subs  map[string]chan chill.Message // per-participant queues; immutable after New

	grpc *grpc.Server
	lis  net.Listener
}

var _ chill.Transport = (*Server)(nil)

// NewServer pre-creates the coordinator inbox and one buffered queue per
// participant (from params.IDs()), then registers the gRPC service on lis.
// Pre-creating the queues is required: a broadcast is buffered for a participant
// that has not Subscribed yet, exactly like MemHub.Endpoint.
func NewServer(params thres.SessionParams, lis net.Listener) *Server {
	s := &Server{
		inbox: make(chan chill.Message, chanBuf),
		subs:  make(map[string]chan chill.Message, params.N),
		grpc:  grpc.NewServer(),
		lis:   lis,
	}
	for _, id := range params.IDs() {
		s.subs[addr(id)] = make(chan chill.Message, chanBuf)
	}
	relaypb.RegisterRelayServer(s.grpc, s)
	return s
}

// Start begins serving in the background. The listener is already accepting, so
// clients may dial as soon as this returns.
func (s *Server) Start() { go func() { _ = s.grpc.Serve(s.lis) }() }

// Addr is the address clients dial.
func (s *Server) Addr() net.Addr { return s.lis.Addr() }

// Close stops the server, gracefully if it completes within 2s.
func (s *Server) Close() {
	done := make(chan struct{})
	go func() { s.grpc.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		s.grpc.Stop()
	}
}

// --- gRPC RelayServer ---

// Send routes a participant's message by its To field: to the coordinator inbox,
// or to a participant queue (unknown recipients are dropped, mirroring MemHub).
func (s *Server) Send(ctx context.Context, env *relaypb.Envelope) (*relaypb.Ack, error) {
	if env.To == "" {
		return nil, status.Error(codes.InvalidArgument, "empty to")
	}
	msg := fromEnvelope(env)
	if env.To == chill.CoordinatorAddr {
		select {
		case s.inbox <- msg:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &relaypb.Ack{}, nil
	}
	if ch, ok := s.subs[env.To]; ok {
		select {
		case ch <- msg:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &relaypb.Ack{}, nil
}

// Subscribe streams the messages queued for req.Addr until the client disconnects.
func (s *Server) Subscribe(req *relaypb.SubscribeRequest, stream relaypb.Relay_SubscribeServer) error {
	if req.Addr == "" {
		return status.Error(codes.InvalidArgument, "empty addr")
	}
	ch, ok := s.subs[req.Addr]
	if !ok {
		return status.Error(codes.NotFound, "unknown addr")
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case msg := <-ch:
			if err := stream.Send(toEnvelope(msg)); err != nil {
				return err
			}
		}
	}
}

// --- thresholdchilldkg.Transport (coordinator side) ---

// Inbox returns the channel of messages addressed to the coordinator.
func (s *Server) Inbox() <-chan chill.Message { return s.inbox }

// Broadcast queues msg for every participant (the coordinator is not a queue, so
// it is naturally excluded), setting From to the coordinator.
func (s *Server) Broadcast(ctx context.Context, msg chill.Message) error {
	msg.From = chill.CoordinatorAddr
	for _, ch := range s.subs {
		select {
		case ch <- msg:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// SendTo queues msg for a single participant (unknown recipient dropped).
func (s *Server) SendTo(ctx context.Context, to string, msg chill.Message) error {
	msg.From = chill.CoordinatorAddr
	msg.To = to
	ch, ok := s.subs[to]
	if !ok {
		return nil
	}
	select {
	case ch <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
