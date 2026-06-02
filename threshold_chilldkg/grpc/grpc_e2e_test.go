package chillgrpc

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	chill "thresholdchilldkg"
	"thresholdchilldkggrpc/relaypb"
)

// fixture builds a session from the exported parent API only.
type fixture struct {
	params  thres.SessionParams
	ids     []thres.Identifier
	hostSks map[thres.Identifier]*secp.PrivateKey
	secrets map[thres.Identifier]thres.SecretKey
	coeffs  map[thres.Identifier][]secp.ModNScalar
}

func newFixture(t *testing.T, min, max uint16) fixture {
	t.Helper()
	f := fixture{
		hostSks: make(map[thres.Identifier]*secp.PrivateKey, max),
		secrets: make(map[thres.Identifier]thres.SecretKey, max),
		coeffs:  make(map[thres.Identifier][]secp.ModNScalar, max),
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

func (f fixture) participant(id thres.Identifier, tr chill.Transport) *chill.Participant {
	return &chill.Participant{
		Params: f.params, Self: id, HostSk: f.hostSks[id],
		Secret: f.secrets[id], Coeffs: f.coeffs[id], Rng: rand.Reader, Transport: tr,
	}
}

type partOut struct {
	id  thres.Identifier
	out thres.DKGOutput
	rec thres.RecoveryData
	err error
}

type coordOut struct {
	rd  thres.RecoveryData
	err error
}

func TestGRPCEndToEnd(t *testing.T) {
	for _, tc := range []struct{ min, max uint16 }{{2, 3}, {3, 5}} {
		tc := tc
		t.Run(fmt.Sprintf("%dof%d", tc.min, tc.max), func(t *testing.T) {
			f := newFixture(t, tc.min, tc.max)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			srv := NewServer(f.params, lis)
			srv.Start()
			defer srv.Close()

			clients := make(map[thres.Identifier]*Client, len(f.ids))
			for _, id := range f.ids {
				c, err := NewClient(lis.Addr().String(), id)
				require.NoError(t, err)
				require.NoError(t, c.Start(ctx))
				clients[id] = c
			}
			defer func() {
				for _, c := range clients {
					_ = c.Close()
				}
			}()

			coordCh := make(chan coordOut, 1)
			go func() {
				rd, err := (&chill.Coordinator{Params: f.params, Transport: srv}).Run(ctx)
				coordCh <- coordOut{rd, err}
			}()

			ch := make(chan partOut, len(f.ids))
			for _, id := range f.ids {
				id := id
				p := f.participant(id, clients[id])
				go func() {
					out, rec, err := p.Run(ctx)
					ch <- partOut{id, out, rec, err}
				}()
			}

			outs := make(map[thres.Identifier]partOut, len(f.ids))
			for range f.ids {
				r := <-ch
				require.NoErrorf(t, r.err, "participant %v", r.id)
				outs[r.id] = r
			}
			cr := <-coordCh
			require.NoError(t, cr.err)

			// Every participant's and the coordinator's recovery blob are byte-identical.
			ref, err := cr.rd.Serialize()
			require.NoError(t, err)
			for _, id := range f.ids {
				b, err := outs[id].rec.Serialize()
				require.NoError(t, err)
				assert.Equalf(t, ref, b, "blob mismatch for %v", id)
			}

			// Round-trip the coordinator's blob and recover every participant's share.
			rd, err := thres.ParseRecoveryData(ref)
			require.NoError(t, err)
			require.NoError(t, rd.Verify())
			for _, id := range f.ids {
				out, err := thres.RecoverShare(rd, f.hostSks[id])
				require.NoErrorf(t, err, "recover %v", id)
				assert.True(t, out.Key.Identifier.Equal(id), "recovered wrong identifier")
				want := outs[id].out.Key.SecretShare
				got := out.Key.SecretShare
				assert.True(t, (*secp.ModNScalar)(&got).Equals((*secp.ModNScalar)(&want)), "recovered share mismatch")
			}
		})
	}
}

// TestGRPCLateSubscriber delays one participant's Subscribe until after the
// coordinator has broadcast cmsg1, proving the server's pre-created per-addr
// buffers hold the broadcast for a not-yet-subscribed participant.
func TestGRPCLateSubscriber(t *testing.T) {
	f := newFixture(t, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := NewServer(f.params, lis)
	srv.Start()
	defer srv.Close()

	late := f.ids[len(f.ids)-1]
	clients := make(map[thres.Identifier]*Client, len(f.ids))
	for _, id := range f.ids {
		c, err := NewClient(lis.Addr().String(), id)
		require.NoError(t, err)
		clients[id] = c
		if !id.Equal(late) {
			require.NoError(t, c.Start(ctx)) // on-time participants subscribe now
		}
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	coordCh := make(chan coordOut, 1)
	go func() {
		rd, err := (&chill.Coordinator{Params: f.params, Transport: srv}).Run(ctx)
		coordCh <- coordOut{rd, err}
	}()

	ch := make(chan partOut, len(f.ids))
	for _, id := range f.ids {
		id := id
		p := f.participant(id, clients[id]) // late participant's Run sends round1 (unary) without subscribing
		go func() {
			out, rec, err := p.Run(ctx)
			ch <- partOut{id, out, rec, err}
		}()
	}

	// Let the coordinator collect all round-1 (incl. the late one's unary Send) and
	// broadcast cmsg1 before the late participant finally subscribes.
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, clients[late].Start(ctx))

	for range f.ids {
		r := <-ch
		require.NoErrorf(t, r.err, "participant %v", r.id)
	}
	require.NoError(t, (<-coordCh).err)
}

// TestGRPCStalledCeremonyTimesOut: with a participant missing, the coordinator
// cannot collect N round-1 messages and the ceremony times out cleanly.
func TestGRPCStalledCeremonyTimesOut(t *testing.T) {
	f := newFixture(t, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := NewServer(f.params, lis)
	srv.Start()
	defer srv.Close()

	present := f.ids[:len(f.ids)-1] // one participant never shows up
	clients := make(map[thres.Identifier]*Client, len(present))
	for _, id := range present {
		c, err := NewClient(lis.Addr().String(), id)
		require.NoError(t, err)
		require.NoError(t, c.Start(ctx))
		clients[id] = c
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	coordCh := make(chan coordOut, 1)
	go func() {
		rd, err := (&chill.Coordinator{Params: f.params, Transport: srv}).Run(ctx)
		coordCh <- coordOut{rd, err}
	}()
	ch := make(chan partOut, len(present))
	for _, id := range present {
		id := id
		p := f.participant(id, clients[id])
		go func() {
			out, rec, err := p.Run(ctx)
			ch <- partOut{id, out, rec, err}
		}()
	}

	assert.Error(t, (<-coordCh).err, "coordinator must error when a participant is missing")
	for range present {
		assert.Error(t, (<-ch).err)
	}
}

// TestGRPCGuards exercises the server's admission guards directly.
func TestGRPCGuards(t *testing.T) {
	f := newFixture(t, 2, 3)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := NewServer(f.params, lis)
	srv.Start()
	defer srv.Close()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	cl := relaypb.NewRelayClient(conn)
	ctx := context.Background()

	_, err = cl.Send(ctx, &relaypb.Envelope{To: ""})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "empty To")

	st, err := cl.Subscribe(ctx, &relaypb.SubscribeRequest{Addr: ""})
	require.NoError(t, err)
	_, err = st.Recv()
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "empty addr")

	st2, err := cl.Subscribe(ctx, &relaypb.SubscribeRequest{Addr: "00ff"})
	require.NoError(t, err)
	_, err = st2.Recv()
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown addr")
}
