package chillgrpc

import (
	"context"
	"errors"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	chill "thresholdchilldkg"
	"thresholdchilldkggrpc/relaypb"
)

// Client is the participant-side transport: it Sends to the coordinator and
// receives its messages over a Subscribe server stream. It satisfies
// thresholdchilldkg.Transport.
type Client struct {
	self   string
	conn   *grpc.ClientConn
	client relaypb.RelayClient
	inbox  chan chill.Message
	cancel context.CancelFunc
}

var _ chill.Transport = (*Client)(nil)

// NewClient dials the coordinator at target over an insecure connection. self is
// this participant's identifier (its address is hex(self.Serialize())).
func NewClient(target string, self thres.Identifier) (*Client, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{
		self:   addr(self),
		conn:   conn,
		client: relaypb.NewRelayClient(conn),
		inbox:  make(chan chill.Message, chanBuf),
	}, nil
}

// Start opens the Subscribe stream and feeds the inbox in the background. It must
// be called before the participant driver runs, so the participant is subscribed
// before it sends round 1. The stream lives until Close or ctx cancellation; on
// any stream error the inbox is closed (the driver then sees ErrProtocol).
func (c *Client) Start(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	stream, err := c.client.Subscribe(sctx, &relaypb.SubscribeRequest{Addr: c.self})
	if err != nil {
		cancel()
		return err
	}
	go func() {
		defer close(c.inbox)
		for {
			env, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case c.inbox <- fromEnvelope(env):
			case <-sctx.Done():
				return
			}
		}
	}()
	return nil
}

// Inbox returns the channel of messages addressed to this participant.
func (c *Client) Inbox() <-chan chill.Message { return c.inbox }

// SendTo delivers msg to the coordinator (the only address a participant uses).
func (c *Client) SendTo(ctx context.Context, to string, msg chill.Message) error {
	msg.From = c.self
	msg.To = to
	_, err := c.client.Send(ctx, toEnvelope(msg))
	return err
}

// Broadcast is never used by a participant (only the coordinator broadcasts).
func (c *Client) Broadcast(ctx context.Context, msg chill.Message) error {
	return errors.New("chillgrpc: participant transport does not broadcast")
}

// Close stops the subscribe stream and closes the connection.
func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	return c.conn.Close()
}
