package thresholdsdk

import (
	"context"
	"testing"
	"time"

	thres "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionRecoveryData runs a full honest session and checks that every
// participant produces the byte-identical shared recovery blob, that it
// round-trips, and that RecoverShare reproduces each participant's key share.
func TestSessionRecoveryData(t *testing.T) {
	f := newSessionFixture(t, 2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	coordEp := f.hub.Endpoint(CoordinatorAddr)
	for _, id := range f.ids {
		f.hub.Endpoint(addrOf(id))
	}

	coord := &dkgCoordinator{Params: f.params, Transport: coordEp}
	parts := make([]*dkgParticipant, 0, len(f.ids))
	for _, id := range f.ids {
		parts = append(parts, f.participant(id, f.hub.Endpoint(addrOf(id))))
	}

	type coordRes struct {
		rd  thres.RecoveryData
		err error
	}
	coordCh := make(chan coordRes, 1)
	go func() { rd, err := coord.Run(ctx); coordCh <- coordRes{rd, err} }()
	ch := make(chan blamePartResult, len(parts))
	for _, p := range parts {
		p := p
		go func() {
			out, rec, err := p.Run(ctx)
			ch <- blamePartResult{p.Self, out, rec, err}
		}()
	}

	results := make(map[thres.Identifier]blamePartResult, len(parts))
	for range parts {
		r := <-ch
		results[r.id] = r
	}
	coord1 := <-coordCh
	require.NoError(t, coord1.err)

	// Shared blob: every participant serializes the identical recovery data.
	var ref []byte
	for i, id := range f.ids {
		require.NoErrorf(t, results[id].err, "participant %v", id)
		blob, err := results[id].rec.Serialize()
		require.NoError(t, err)
		if i == 0 {
			ref = blob
			continue
		}
		assert.Equalf(t, ref, blob, "participant %v produced a different recovery blob", id)
	}

	// The coordinator serves the same canonical blob.
	coordBlob, err := coord1.rd.Serialize()
	require.NoError(t, err)
	assert.Equal(t, ref, coordBlob, "coordinator's recovery blob differs from participants'")

	// Round-trip, then recover each participant's KeyPackage from the one blob.
	rd, err := thres.ParseRecoveryData(ref)
	require.NoError(t, err)
	require.NoError(t, rd.Verify())
	for _, id := range f.ids {
		out, err := thres.RecoverShare(rd, f.hostSks[id])
		require.NoErrorf(t, err, "recover %v", id)
		require.Truef(t, out.Key.Identifier.Equal(id), "recovered wrong identifier for %v", id)
		want := results[id].out.Key.SecretShare
		got := out.Key.SecretShare
		assert.Truef(t, (*secp.ModNScalar)(&got).Equals((*secp.ModNScalar)(&want)), "recovered share mismatch for %v", id)
	}
}
