package thresholdcore

import (
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// TestLeaderGroupPubkeyMatchesCeremony: the exported LeaderGroupPubkey (computed
// from a0 alone) equals both the reference computation and the ThresholdPubkey a
// real leader/slave ceremony produces. This is what lets a leader publish its
// group key without waiting for a member to join.
func TestLeaderGroupPubkeyMatchesCeremony(t *testing.T) {
	leaderKey, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	leaderSecret := leaderKey.Serialize()

	got, err := LeaderGroupPubkey(leaderSecret)
	require.NoError(t, err)
	require.Equal(t, leaderExpectedPubkey(t, leaderSecret), got, "must match reference tweak computation")

	// leader + 2 slaves (n=3, t=2): every participant's ThresholdPubkey matches.
	keys := append([]*secp.PrivateKey{leaderKey}, leaderGenKeys(t, 2)...)
	outs := runLeaderCeremony(t, keys, 0, leaderSecret, 2)
	for i, o := range outs {
		require.Equalf(t, got, o.ThresholdPubkey, "ceremony participant %d pubkey", i)
	}
}

// TestLeaderGroupPubkeyRejectsBadSecret: the scalar rules match BIPParticipantStep1.
func TestLeaderGroupPubkeyRejectsBadSecret(t *testing.T) {
	_, err := LeaderGroupPubkey(make([]byte, 31)) // wrong length
	require.Error(t, err)
	_, err = LeaderGroupPubkey(make([]byte, 32)) // zero scalar
	require.Error(t, err)
}
