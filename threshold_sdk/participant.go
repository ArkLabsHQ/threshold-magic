package thresholdsdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	chill "thresholdchilldkg"
	chillgrpc "thresholdchilldkggrpc"
)

// ErrSelfNotInParams is returned when the host key's public key matches no
// participant in the session parameters.
var ErrSelfNotInParams = errors.New("thresholdsdk: host key not among session participants")

// Participant runs the key-holder side of a ChillDKG ceremony over gRPC and
// persists the public RecoveryData blob. No secret is stored: its share is
// recovered on demand from the blob plus its host key.
type Participant struct {
	params    core.SessionParams
	self      core.Identifier
	hostSk    *secp.PrivateKey
	coordAddr string
	store     Store
}

// HostKeyFromHex parses a hex-encoded 32-byte secp256k1 host secret, rejecting an
// out-of-range length and the zero key. It is a convenience for callers holding
// the secret as a string; the SDK itself takes a *secp.PrivateKey.
func HostKeyFromHex(s string) (*secp.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("thresholdsdk: host secret must be 32 bytes")
	}
	sk := secp.PrivKeyFromBytes(b)
	if sk.Key.IsZero() {
		return nil, errors.New("thresholdsdk: host secret is zero")
	}
	return sk, nil
}

// NewParticipant builds a participant for params. self is found by matching
// hostSk's public key against params.HostPubs (host keys are unique), so no
// identifier need be supplied. coordinatorAddr is the relay's gRPC address; store
// persists the outputs.
func NewParticipant(params core.SessionParams, hostSk *secp.PrivateKey, coordinatorAddr string, store Store) (*Participant, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if hostSk == nil {
		return nil, errors.New("thresholdsdk: nil host key")
	}
	if store == nil {
		return nil, errors.New("thresholdsdk: nil store")
	}
	self, err := identify(params, hostSk.PubKey())
	if err != nil {
		return nil, err
	}
	return &Participant{
		params:    params,
		self:      self,
		hostSk:    hostSk,
		coordAddr: coordinatorAddr,
		store:     store,
	}, nil
}

// identify returns the identifier whose host public key matches pub.
func identify(params core.SessionParams, pub *secp.PublicKey) (core.Identifier, error) {
	want := pub.SerializeCompressed()
	for id, p := range params.HostPubs {
		if p != nil && bytes.Equal(p.SerializeCompressed(), want) {
			return id, nil
		}
	}
	return core.Identifier{}, ErrSelfNotInParams
}

// Run executes the ceremony over gRPC and persists the public RecoveryData blob
// keyed by the produced group verifying key, returning the key package. Each call
// runs a fresh ceremony (a new key); it is not idempotent.
func (p *Participant) Run(ctx context.Context) (core.KeyPackage, error) {
	// Fresh per-run contribution material — never derived from the host key.
	sec, err := secp.GeneratePrivateKey()
	if err != nil {
		return core.KeyPackage{}, err
	}
	coeffs, err := core.GenerateCoefficients(p.params.T)
	if err != nil {
		return core.KeyPackage{}, err
	}

	client, err := chillgrpc.NewClient(p.coordAddr, p.self)
	if err != nil {
		return core.KeyPackage{}, err
	}
	defer client.Close()
	if err := client.Start(ctx); err != nil {
		return core.KeyPackage{}, err
	}

	driver := &chill.Participant{
		Params:    p.params,
		Self:      p.self,
		HostSk:    p.hostSk,
		Secret:    core.SecretKey{Scalar: sec.Key},
		Coeffs:    coeffs,
		Rng:       rand.Reader,
		Transport: client,
	}
	out, rec, err := driver.Run(ctx)
	if err != nil {
		return core.KeyPackage{}, err
	}

	blob, err := rec.Serialize()
	if err != nil {
		return core.KeyPackage{}, err
	}
	groupKey, err := out.Key.VerifyingKey.SerializeCompressed()
	if err != nil {
		return core.KeyPackage{}, err
	}
	if err := p.store.PutRecovery(groupKey, blob); err != nil {
		return core.KeyPackage{}, err
	}
	return out.Key, nil
}

// LoadKeyPackage reconstructs the key package for the given group verifying key
// (33-byte compressed) from storage: it parses the stored RecoveryData and
// recovers the share with the host secret. RecoverShare re-verifies the success
// certificate and re-checks the share against the certified group commitment, so
// the returned package is trusted without any secret being kept at rest.
func (p *Participant) LoadKeyPackage(groupKey []byte) (core.KeyPackage, error) {
	blob, err := p.store.GetRecovery(groupKey)
	if err != nil {
		return core.KeyPackage{}, err
	}
	rd, err := core.ParseRecoveryData(blob)
	if err != nil {
		return core.KeyPackage{}, err
	}
	out, err := core.RecoverShare(rd, p.hostSk)
	if err != nil {
		return core.KeyPackage{}, err
	}
	return out.Key, nil
}

// Close closes the injected store.
func (p *Participant) Close() error { return p.store.Close() }
