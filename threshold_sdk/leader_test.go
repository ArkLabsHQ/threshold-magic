package thresholdsdk

import (
	"context"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// testLabel is the secret label used across the leader tests.
const testLabel = "vault"

func mustKey(t *testing.T) *secp.PrivateKey {
	t.Helper()
	k, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	return k
}

// waitGroupSize blocks until label's last successful re-DKG covered exactly n
// members (GroupSize is set only on success, so this also means the re-DKG finished).
func waitGroupSize(t *testing.T, l *Leader, label string, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if l.GroupSize(label) == n {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("group size for %q never reached %d (got %d)", label, n, l.GroupSize(label))
}

// reshareUntil drives reshares of label (via driver, a joined follower) until the
// leader's last successful re-DKG for label covers exactly n members. Repeated
// requests are harmless: each re-runs the DKG over the current committee, reusing a0.
func reshareUntil(ctx context.Context, t *testing.T, l *Leader, driver *Follower, label string, n int) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		_ = driver.RequestReshare(ctx, label)
		time.Sleep(300 * time.Millisecond)
		if l.GroupSize(label) == n {
			return
		}
	}
	t.Fatalf("group size for %q never reached %d (got %d)", label, n, l.GroupSize(label))
}

// startFollower launches a joining follower daemon (store closed at test end).
func startFollower(ctx context.Context, t *testing.T, hostSk *secp.PrivateKey, addr string, leaderPub *secp.PublicKey) *Follower {
	t.Helper()
	st := newMemStore()
	t.Cleanup(func() { _ = st.Close() })
	s, err := NewJoiningFollower(hostSk, addr, leaderPub, st)
	require.NoError(t, err)
	go func() { _ = s.Serve(ctx) }()
	return s
}

// TestLeaderDynamicJoinBan: a label's public key is stable as members join and are
// banned — the headline property of the custodial leader/follower construction.
func TestLeaderDynamicJoinBan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	lstore := newMemStore()
	leader, err := NewLeader(mustKey(t), "127.0.0.1:0", lstore)
	require.NoError(t, err)
	defer leader.Close()
	go func() { _ = leader.Serve(ctx) }()
	addr := leader.Addr().String()

	// Two followers join; a reshare brings the group to 3 (leader + 2). driver is
	// used to drive reshares (s1 is banned later).
	s1 := mustKey(t)
	startFollower(ctx, t, s1, addr, leader.HostPubKey())
	driver := startFollower(ctx, t, mustKey(t), addr, leader.HostPubKey())
	reshareUntil(ctx, t, leader, driver, testLabel, 3)
	pk1, err := leader.GroupPubKey(testLabel)
	require.NoError(t, err)
	require.Len(t, pk1, 33)

	// A third follower joins → group of 4; the key must not change.
	startFollower(ctx, t, mustKey(t), addr, leader.HostPubKey())
	reshareUntil(ctx, t, leader, driver, testLabel, 4)
	pk2, err := leader.GroupPubKey(testLabel)
	require.NoError(t, err)
	require.Equal(t, pk1, pk2, "pubkey must not change when a member joins")

	// Ban one follower → group of 3; the key must still not change.
	require.NoError(t, leader.Ban(ctx, s1.PubKey().SerializeCompressed()))
	waitGroupSize(t, leader, testLabel, 3)
	pk3, err := leader.GroupPubKey(testLabel)
	require.NoError(t, err)
	require.Equal(t, pk1, pk3, "pubkey must not change when a member is banned")
}

// TestLeaderSecretPersistence confirms the leader generates a label's a0 once and
// reuses it from the store, which keeps that label's group key stable across re-DKGs.
func TestLeaderSecretPersistence(t *testing.T) {
	store := newMemStore()
	defer store.Close()
	hostSk := mustKey(t)

	l1, err := NewLeader(hostSk, "127.0.0.1:0", store)
	require.NoError(t, err)
	a0a, err := l1.secretFor(testLabel)
	require.NoError(t, err)

	// A fresh Leader over the SAME store must load the persisted a0, not regenerate.
	l2, err := NewLeader(hostSk, "127.0.0.1:0", store)
	require.NoError(t, err)
	a0b, err := l2.secretFor(testLabel)
	require.NoError(t, err)

	require.Equal(t, a0a, a0b, "leader a0 must persist and be reused")
	require.Len(t, a0a, 32)

	// A different label gets its own independent a0.
	other, err := l1.secretFor("other")
	require.NoError(t, err)
	require.NotEqual(t, a0a, other, "distinct labels must have distinct secrets")
}
