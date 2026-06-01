package thresholdchilldkg

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionEndToEndOverMemTransport(t *testing.T) {
	min, max := uint16(2), uint16(3)

	// Build participants with host keys, contribution secrets, and coefficients.
	ids := make([]thres.Identifier, 0, max)
	hostSks := make(map[thres.Identifier]*secp.PrivateKey, max)
	hostPubs := make(map[thres.Identifier]*secp.PublicKey, max)
	secrets := make(map[thres.Identifier]thres.SecretKey, max)
	coeffs := make(map[thres.Identifier][]secp.ModNScalar, max)

	for i := uint16(1); i <= max; i++ {
		id, err := thres.IdentifierFromUint16(i)
		require.NoError(t, err)
		sk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		sec, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		cs, err := thres.GenerateCoefficients(min)
		require.NoError(t, err)

		ids = append(ids, id)
		hostSks[id] = sk
		hostPubs[id] = sk.PubKey()
		secrets[id] = thres.SecretKey{Scalar: sec.Key}
		coeffs[id] = cs
	}

	params, err := thres.NewSessionParams(min, hostPubs)
	require.NoError(t, err)
	require.NoError(t, params.Validate())

	hub := NewMemHub()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Coordinator endpoint must exist before participants broadcast.
	coordEndpoint := hub.Endpoint(CoordinatorAddr)
	for _, id := range ids {
		hub.Endpoint(addrOf(id))
	}

	type result struct {
		out thres.DKGOutput
		rec thres.RecoveryData
		err error
	}
	results := make(chan struct {
		id thres.Identifier
		r  result
	}, max)

	coordErr := make(chan error, 1)
	go func() {
		coord := &Coordinator{Params: params, Transport: coordEndpoint}
		_, cerr := coord.Run(ctx)
		coordErr <- cerr
	}()

	for _, id := range ids {
		id := id
		p := &Participant{
			Params:    params,
			Self:      id,
			HostSk:    hostSks[id],
			Secret:    secrets[id],
			Coeffs:    coeffs[id],
			Rng:       rand.Reader,
			Transport: hub.Endpoint(addrOf(id)),
		}
		go func() {
			out, rec, err := p.Run(ctx)
			results <- struct {
				id thres.Identifier
				r  result
			}{id, result{out, rec, err}}
		}()
	}

	outputs := make(map[thres.Identifier]thres.DKGOutput, max)
	for i := 0; i < int(max); i++ {
		got := <-results
		require.NoErrorf(t, got.r.err, "participant %v", got.id)
		assert.NotEmpty(t, got.r.rec.Certificate, "recovery data carries the certificate")
		assert.Len(t, got.r.rec.Certificate, int(max))
		outputs[got.id] = got.r.out
	}
	require.NoError(t, <-coordErr)

	// All participants agree on the group verifying key.
	var ref thres.VerifyingKey
	first := true
	for _, out := range outputs {
		if first {
			ref = out.Key.VerifyingKey
			first = false
			continue
		}
		vk := out.Key.VerifyingKey
		assert.True(t, ref.E.EquivalentNonConst(&vk.E), "group key agreement")
	}

	// Reconstruction equals the sum of contribution secrets.
	shares := make(map[thres.Identifier]thres.SecretShare, max)
	for id, out := range outputs {
		shares[id] = out.Key.SecretShare
	}
	reconstructed, err := thres.Reconstruct(min, shares)
	require.NoError(t, err)

	var expected secp.ModNScalar
	for _, id := range ids {
		s := secrets[id].Scalar
		expected.Add(&s)
	}
	assert.True(t, reconstructed.Scalar.Equals(&expected), "reconstructed key matches sum of secrets")
}
