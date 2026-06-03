package thresholdsdk

import (
	"context"
	"errors"
	"net"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
)

// Coordinator runs the untrusted gRPC relay side of a ChillDKG ceremony and
// persists the resulting public RecoveryData blob. It holds no secret material,
// so it needs no host key.
type Coordinator struct {
	params core.SessionParams
	store  Store
	lis    net.Listener
	srv    *Server
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
		srv:    NewServer(params, lis),
	}, nil
}

// Addr is the resolved listen address; participants dial it.
func (c *Coordinator) Addr() net.Addr { return c.lis.Addr() }

// Run serves the relay and drives the ceremony, then persists the RecoveryData
// blob keyed by the group verifying key it produced and returns it. Each call
// runs a fresh ceremony (a new key); it is not idempotent.
func (c *Coordinator) Run(ctx context.Context) (core.RecoveryData, error) {
	c.srv.Start()
	rd, err := (&dkgCoordinator{Params: c.params, Transport: c.srv}).Run(ctx)
	if err != nil {
		return core.RecoveryData{}, err
	}
	blob, err := rd.Serialize()
	if err != nil {
		return core.RecoveryData{}, err
	}
	vk, err := rd.GroupVerifyingKey()
	if err != nil {
		return core.RecoveryData{}, err
	}
	groupKey, err := vk.SerializeCompressed()
	if err != nil {
		return core.RecoveryData{}, err
	}
	if err := c.store.PutRecovery(groupKey, blob); err != nil {
		return core.RecoveryData{}, err
	}
	return rd, nil
}

// Close stops the relay (gracefully) and closes the store.
func (c *Coordinator) Close() error {
	c.srv.Close()
	return c.store.Close()
}
