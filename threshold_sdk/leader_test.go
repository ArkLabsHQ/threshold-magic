package thresholdsdk

import (
	"context"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func mustKey(t *testing.T) *secp.PrivateKey {
	t.Helper()
	k, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	return k
}

// waitGroupSize blocks until the leader's last successful re-DKG covered exactly n
// members (GroupSize is set only on success, so this also means the re-DKG finished).
func waitGroupSize(t *testing.T, l *Leader, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if l.GroupSize() == n {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("group size never reached %d (got %d)", n, l.GroupSize())
}

// startFollower launches a joining follower daemon (store closed at test end).
func startFollower(ctx context.Context, t *testing.T, hostSk *secp.PrivateKey, addr string, leaderPub *secp.PublicKey) {
	t.Helper()
	st, err := OpenBadgerStore("")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	s, err := NewJoiningFollower(hostSk, addr, leaderPub, st)
	require.NoError(t, err)
	go func() { _ = s.Serve(ctx) }()
}

// TestLeaderDynamicJoinBan: the group's public key is stable as members join and are
// banned — the headline property of the custodial leader/follower construction.
func TestLeaderDynamicJoinBan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lstore, err := OpenBadgerStore("")
	require.NoError(t, err)
	leader, err := NewLeader(mustKey(t), "127.0.0.1:0", lstore)
	require.NoError(t, err)
	defer leader.Close()
	go func() { _ = leader.Serve(ctx) }()
	addr := leader.Addr().String()

	// Two followers join → group of 3 (leader + 2).
	s1 := mustKey(t)
	startFollower(ctx, t, s1, addr, leader.Pub())
	startFollower(ctx, t, mustKey(t), addr, leader.Pub())
	waitGroupSize(t, leader, 3)
	pk1, err := leader.Pubkey()
	require.NoError(t, err)
	require.Len(t, pk1, 33)

	// A third follower joins → group of 4; the key must not change.
	startFollower(ctx, t, mustKey(t), addr, leader.Pub())
	waitGroupSize(t, leader, 4)
	pk2, err := leader.Pubkey()
	require.NoError(t, err)
	require.Equal(t, pk1, pk2, "pubkey must not change when a member joins")

	// Ban one follower → group of 3; the key must still not change.
	require.NoError(t, leader.Ban(ctx, s1.PubKey().SerializeCompressed()))
	waitGroupSize(t, leader, 3)
	pk3, err := leader.Pubkey()
	require.NoError(t, err)
	require.Equal(t, pk1, pk3, "pubkey must not change when a member is banned")
}

// TestLeaderSecretPersistence confirms the leader generates a0 once and reuses it
// from the store, which is what keeps the group key stable across re-DKGs.
func TestLeaderSecretPersistence(t *testing.T) {
	store, err := OpenBadgerStore("")
	require.NoError(t, err)
	defer store.Close()
	hostSk := mustKey(t)

	l1, err := NewLeader(hostSk, "127.0.0.1:0", store)
	require.NoError(t, err)
	a0a, err := l1.secret()
	require.NoError(t, err)

	// A fresh Leader over the SAME store must load the persisted a0, not regenerate.
	l2, err := NewLeader(hostSk, "127.0.0.1:0", store)
	require.NoError(t, err)
	a0b, err := l2.secret()
	require.NoError(t, err)

	require.Equal(t, a0a, a0b, "leader a0 must persist and be reused")
	require.Len(t, a0a, 32)
}
