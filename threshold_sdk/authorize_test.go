package thresholdsdk

import (
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// TestWithAuthorizeGatesJoin: a WithAuthorize callback is consulted on every Join,
// even when the proof-of-possession is valid. An unauthorized host key is refused;
// an authorized one is admitted.
func TestWithAuthorizeGatesJoin(t *testing.T) {
	allowed := mustKey(t)
	denied := mustKey(t)

	allow := func(hostPubkey []byte) bool {
		return string(hostPubkey) == string(allowed.PubKey().SerializeCompressed())
	}

	leader, err := NewLeader(mustKey(t), "127.0.0.1:0", newMemStore(), WithAuthorize(allow))
	require.NoError(t, err)
	defer leader.Close()

	proofFor := func(k *secp.PrivateKey) []byte {
		p, perr := signJoinProof(k)
		require.NoError(t, perr)
		return p
	}

	// Denied key: valid proof, but not authorized.
	_, err = leader.handleJoin(denied.PubKey().SerializeCompressed(), proofFor(denied))
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authorized")

	// Allowed key: valid proof and authorized -> gets an identifier.
	id, err := leader.handleJoin(allowed.PubKey().SerializeCompressed(), proofFor(allowed))
	require.NoError(t, err)
	require.NotEqual(t, leader.self, id)
}

// TestNilAuthorizeAllowsJoin: omitting WithAuthorize keeps the default behavior —
// any host key with a valid proof may join.
func TestNilAuthorizeAllowsJoin(t *testing.T) {
	leader, err := NewLeader(mustKey(t), "127.0.0.1:0", newMemStore())
	require.NoError(t, err)
	defer leader.Close()

	k := mustKey(t)
	proof, err := signJoinProof(k)
	require.NoError(t, err)
	_, err = leader.handleJoin(k.PubKey().SerializeCompressed(), proof)
	require.NoError(t, err)
}
