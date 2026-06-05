package thresholdsdk

// Insecure gRPC transport: the leader runs Server (a gRPC relay); each follower
// runs Client. Both implement Transport.

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"thresholdsdk/relaypb"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative relaypb/relay.proto

// chanBuf is the per-endpoint inbox buffer size (gRPC server and client).
const chanBuf = 256

// gracefulStopTimeout bounds GracefulStop on Close before a hard Stop.
const gracefulStopTimeout = 2 * time.Second

// addr is the hex transport address of an identifier (duplicate of addrOf).
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

	inbox chan Message // messages addressed to the coordinator

	mu   sync.RWMutex            // guards subs (mutated by Join/ban in leader sessions)
	subs map[string]chan Message // per-participant queues

	// onJoin, when set (leader/follower sessions), admits a new party: it verifies the
	// request, creates the party's queue (addSub), and returns its identifier. nil in
	// a classic coordinator session, where Join is unsupported.
	onJoin func(hostPubkey, proof []byte) (thres.Identifier, error)

	grpc *grpc.Server
	lis  net.Listener
}

// addSub creates (idempotently) the queue for addr and returns it.
func (s *Server) addSub(addr string) chan Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.subs[addr]
	if !ok {
		ch = make(chan Message, chanBuf)
		s.subs[addr] = ch
	}
	return ch
}

// removeSub drops addr's queue from the routing table. It does not close the channel
// (a concurrent Broadcast may hold a snapshot of it); the removed party disconnects
// on the msgRemoved it was sent just before, ending its Subscribe stream.
func (s *Server) removeSub(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, addr)
}

// sub looks up addr's queue.
func (s *Server) sub(addr string) (chan Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch, ok := s.subs[addr]
	return ch, ok
}

var _ Transport = (*Server)(nil)

// newDynamicServer creates the leader's relay with no pre-created participant
// queues — the leader/follower daemon adds them as members join (addSub) and drops
// them on ban (removeSub).
func newDynamicServer(lis net.Listener) *Server {
	s := &Server{
		inbox: make(chan Message, chanBuf),
		subs:  make(map[string]chan Message),
		grpc:  grpc.NewServer(),
		lis:   lis,
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
// or to a participant queue (unknown recipients are dropped).
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
	if ch, ok := s.sub(env.To); ok {
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
	ch, ok := s.sub(req.Addr)
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

// Join admits a new party in a leader/follower session via the onJoin callback (which
// verifies the request and creates the party's queue). Unsupported in a classic
// coordinator session (onJoin nil).
func (s *Server) Join(ctx context.Context, req *relaypb.JoinRequest) (*relaypb.JoinResponse, error) {
	if s.onJoin == nil {
		return nil, status.Error(codes.Unimplemented, "join not supported")
	}
	id, err := s.onJoin(req.HostPubkey, req.Proof)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &relaypb.JoinResponse{Identifier: id.Serialize()}, nil
}

// --- Transport (coordinator side) ---

// Inbox returns the channel of messages addressed to the coordinator.
func (s *Server) Inbox() <-chan Message { return s.inbox }

// Broadcast queues msg for every participant (the coordinator is not a queue, so
// it is naturally excluded), setting From to the coordinator.
func (s *Server) Broadcast(ctx context.Context, msg Message) error {
	msg.From = CoordinatorAddr
	// Snapshot the channels under the read lock so a concurrent Join/ban can't race
	// the iteration.
	s.mu.RLock()
	chans := make([]chan Message, 0, len(s.subs))
	for _, ch := range s.subs {
		chans = append(chans, ch)
	}
	s.mu.RUnlock()
	for _, ch := range chans {
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
	ch, ok := s.sub(to)
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
