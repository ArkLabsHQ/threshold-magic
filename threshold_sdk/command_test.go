package thresholdsdk

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLeaderCommandAuth: a leader command verifies only against the leader's host key
// and only if untampered — so the untrusted relay can't forge or alter a rekey/ban.
func TestLeaderCommandAuth(t *testing.T) {
	leader := mustKey(t)
	other := mustKey(t)

	cmd := leaderCmd{Kind: cmdRekey, Epoch: 7, Threshold: 2, Leader: "ab", Members: map[string]string{"01": "02"}}
	payload, err := signCommand(leader, cmd)
	require.NoError(t, err)

	got, err := verifyCommand(payload, leader.PubKey())
	require.NoError(t, err)
	require.Equal(t, uint64(7), got.Epoch)

	// A different signer is rejected.
	_, err = verifyCommand(payload, other.PubKey())
	require.Error(t, err, "command signed by a different key must not verify")

	// Tampering anywhere invalidates it.
	bad := append([]byte(nil), payload...)
	bad[len(bad)-3] ^= 0xff
	_, err = verifyCommand(bad, leader.PubKey())
	require.Error(t, err, "tampered command must not verify")
}

// TestJoinProofAuth: a join proof verifies only for the key that produced it, so a
// party cannot register a host key it does not control.
func TestJoinProofAuth(t *testing.T) {
	k := mustKey(t)
	other := mustKey(t)

	proof, err := signJoinProof(k)
	require.NoError(t, err)
	require.True(t, verifyJoinProof(k.PubKey(), proof))
	require.False(t, verifyJoinProof(other.PubKey(), proof), "proof must not verify for another key")
}
