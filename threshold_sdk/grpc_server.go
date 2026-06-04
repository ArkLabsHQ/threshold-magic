package thresholdsdk

// Insecure gRPC transport: the coordinator runs Server (a gRPC relay); each
// participant runs Client. Both implement Transport, with the same semantics as
// MemHub.

import (
	"context"
	"encoding/hex"
	"net"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"thresholdsdk/relaypb"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative relaypb/relay.proto

// chanBuf is the per-endpoint inbox buffer size, shared by the gRPC server/client
// and the in-memory MemHub.
const chanBuf = 256

// gracefulStopTimeout bounds GracefulStop on Close before a hard Stop.
const gracefulStopTimeout = 2 * time.Second

// addr is the transport address of an identifier — identical to the parent's
// addrOf (hex of the serialized scalar).
func addr(id thres.Identifier) string { return hex.EncodeToString(id.Serialize()) }

func toEnvelope(m Message) *relaypb.Envelope {
	return &relaypb.Envelope{Type: m.Type, From: m.From, To: m.To, Payload: m.Payload}
}

func fromEnvelope(e *relaypb.Envelope) Message {
	return Message{Type: e.Type, From: e.From, To: e.To, Payload: e.Payload}
}

// Server is the coordinator-side transport: a gRPC relay that also satisfies
// Transport. Participants Send to it (routed to the coordinator
// inbox) and Subscribe to receive the messages addressed to them.
type Server struct {
	relaypb.UnimplementedRelayServer

	inbox chan Message            // messages addressed to the coordinator
	subs  map[string]chan Message // per-participant queues; immutable after New

	grpc *grpc.Server
	lis  net.Listener
}

var _ Transport = (*Server)(nil)

// NewServer pre-creates the coordinator inbox and one buffered queue per
// participant (from params.IDs()), then registers the gRPC service on lis.
// Pre-creating the queues is required: a broadcast is buffered for a participant
// that has not Subscribed yet, exactly like MemHub.Endpoint.
func NewServer(params thres.SessionParams, lis net.Listener) *Server {
	s := &Server{
		inbox: make(chan Message, chanBuf),
		subs:  make(map[string]chan Message, params.N),
		grpc:  grpc.NewServer(),
		lis:   lis,
	}
	for _, id := range params.IDs() {
		s.subs[addr(id)] = make(chan Message, chanBuf)
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
	case <-time.After(gracefulStopTimeout):
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
	if env.To == CoordinatorAddr {
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

// --- Transport (coordinator side) ---

// Inbox returns the channel of messages addressed to the coordinator.
func (s *Server) Inbox() <-chan Message { return s.inbox }

// Broadcast queues msg for every participant (the coordinator is not a queue, so
// it is naturally excluded), setting From to the coordinator.
func (s *Server) Broadcast(ctx context.Context, msg Message) error {
	msg.From = CoordinatorAddr
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
func (s *Server) SendTo(ctx context.Context, to string, msg Message) error {
	msg.From = CoordinatorAddr
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
