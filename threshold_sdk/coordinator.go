package thresholdsdk

import (
	"context"
	"errors"
	"net"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	chill "thresholdchilldkg"
	chillgrpc "thresholdchilldkggrpc"
)

// Coordinator runs the untrusted gRPC relay side of a ChillDKG ceremony and
// persists the resulting public RecoveryData blob. It holds no secret material,
// so it needs no host key.
type Coordinator struct {
	params core.SessionParams
	store  Store
	lis    net.Listener
	srv    *chillgrpc.Server
}

// NewCoordinator binds a gRPC listener on listenAddr and prepares the relay. Use
// a ":0" port to let the OS choose one, then read it back with Addr before the
// participants dial. store persists the RecoveryData blob.
func NewCoordinator(params core.SessionParams, listenAddr string, store Store) (*Coordinator, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("thresholdsdk: nil store")
	}
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &Coordinator{
		params: params,
		store:  store,
		lis:    lis,
		srv:    chillgrpc.NewServer(params, lis),
	}, nil
}

// Addr is the resolved listen address; participants dial it.
func (c *Coordinator) Addr() net.Addr { return c.lis.Addr() }

// Run serves the relay and drives the ceremony, persisting the RecoveryData blob
// before returning it. If a blob is already stored for these params, it is parsed
// and returned without re-running.
func (c *Coordinator) Run(ctx context.Context) (core.RecoveryData, error) {
	switch blob, err := c.store.GetRecovery(c.params.SessionID); {
	case err == nil:
		return core.ParseRecoveryData(blob)
	case !errors.Is(err, ErrNotFound):
		return core.RecoveryData{}, err
	}

	c.srv.Start()
	rd, err := (&chill.Coordinator{Params: c.params, Transport: c.srv}).Run(ctx)
	if err != nil {
		return core.RecoveryData{}, err
	}
	blob, err := rd.Serialize()
	if err != nil {
		return core.RecoveryData{}, err
	}
	if err := c.store.PutRecovery(c.params.SessionID, blob); err != nil {
		return core.RecoveryData{}, err
	}
	return rd, nil
}

// Close stops the relay (gracefully) and closes the store.
func (c *Coordinator) Close() error {
	c.srv.Close()
	return c.store.Close()
}
