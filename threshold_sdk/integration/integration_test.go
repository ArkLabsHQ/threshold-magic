//go:build integration

package thresholdsdkintegration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	dkgImage       = "thresholdsdk-dkgnode:itest"
	relayPort      = "9000"
	adminPort      = "9100"
	totalFollowers = 5 // joined incrementally (1..5), then 3 are banned back down
)

// TestDockerLeaderFollowerDKG drives one long-lived leader through a full membership
// ramp over a real Docker network — five followers join one at a time, then three are
// banned — asserting at every step that (a) the group public key never moves (the
// leader's secret a0 is fixed) and (b) the signing threshold tracks the majority of
// the committee, t = floor(n/2)+1 with n = leader + followers:
//
//	joins: n = 2 3 4 5 6  ->  t = 2 2 3 3 4
//	bans:  n = 5 4 3      ->  t = 3 3 2
//
// size and t are read from the leader's /status endpoint, which only advances after a
// re-DKG fully succeeds — so each observed (size, t) is proof that transition completed.
func TestDockerLeaderFollowerDKG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// Skip cleanly when Docker is unavailable (the build tag already keeps this out
	// of the default test sweep).
	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	if err := provider.Health(ctx); err != nil {
		t.Skipf("docker daemon not healthy: %v", err)
	}

	// Leader key: the test holds it, so followers can pin the leader's host key
	// directly (LEADER_PUB) without scraping it from logs.
	leaderSk, err := secp.GeneratePrivateKey()
	require.NoError(t, err)
	leaderHostpub := hex.EncodeToString(leaderSk.PubKey().SerializeCompressed())

	followerSecrets := make([]string, totalFollowers)
	for i := range followerSecrets {
		sk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		followerSecrets[i] = hex.EncodeToString(sk.Serialize())
	}

	buildImage(ctx, t)

	net, err := network.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(context.Background()) })

	// Leader: the relay port (9000) is reached by followers over the Docker network
	// alias; the admin port (9100) is exposed to the host so the test can drive bans
	// and read group status. Wait on LEADER-LISTENING (the relay is then accepting);
	// the status poll below tolerates the admin server still binding.
	leader, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          dkgImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"leader"}},
			ExposedPorts:   []string{adminPort + "/tcp"},
			Env: map[string]string{
				"ROLE":        "leader",
				"HOST_SECRET": hex.EncodeToString(leaderSk.Serialize()),
				"LISTEN_ADDR": ":" + relayPort,
				"ADMIN_ADDR":  ":" + adminPort,
			},
			WaitingFor: wait.ForLog("LEADER-LISTENING").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = leader.Terminate(context.Background()) })

	admin := adminBase(ctx, t, leader)
	re := regexp.MustCompile(`RESULT=([0-9a-fA-F]{66})`)
	followers := make([]testcontainers.Container, totalFollowers)
	majority := func(n int) int { return n/2 + 1 } // expected MajorityPolicy, coded independently
	var groupKey string

	// --- Joins: followers up one at a time; t tracks the majority, key must not move.
	for i := 0; i < totalFollowers; i++ {
		followers[i] = startFollower(ctx, t, net.Name, followerSecrets[i], leaderHostpub)
		require.NoErrorf(t, wait.ForLog("DKG-OK").WithStartupTimeout(120*time.Second).WaitUntilReady(ctx, followers[i]),
			"follower %d did not reach DKG-OK", i)
		n := i + 2 // leader + (i+1) followers
		st := waitStatusSize(ctx, t, admin, n, 90*time.Second)
		require.Equalf(t, majority(n), st.T, "threshold wrong at n=%d", n)
		if groupKey == "" {
			groupKey = st.Key // first successful DKG fixes the key
		}
		require.Equalf(t, groupKey, st.Key, "group key changed at n=%d", n)
		require.Equalf(t, groupKey, extractResult(ctx, t, followers[i], re), "follower %d derived a different group key", i)
		t.Logf("join %d: %d-of-%d, key %s…", i+1, st.T, n, groupKey[:8])
	}

	// --- Bans: evict three members, top-down. Banning the follower at index idx leaves
	// leader + idx followers, i.e. n = idx+1; t follows the majority back down, key holds.
	for _, idx := range []int{4, 3, 2} {
		require.NoError(t, postBan(ctx, t, admin, hostpubHex(t, followerSecrets[idx])))
		waitLog(ctx, t, followers[idx], "removed from the group", 60*time.Second) // victim exits with ErrRemoved
		n := idx + 1
		st := waitStatusSize(ctx, t, admin, n, 90*time.Second)
		require.Equalf(t, majority(n), st.T, "threshold wrong after banning follower %d (n=%d)", idx, n)
		require.Equalf(t, groupKey, st.Key, "group key changed after banning follower %d", idx)
		t.Logf("ban f%d: %d-of-%d, key stable", idx, st.T, n)
	}
}

// startFollower launches a follower container that joins the leader dynamically, and
// registers its teardown.
func startFollower(ctx context.Context, t *testing.T, netName, secret, leaderPub string) testcontainers.Container {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:    dkgImage,
			Networks: []string{netName},
			Env: map[string]string{
				"ROLE":        "follower",
				"COORD_ADDR":  "leader:" + relayPort,
				"HOST_SECRET": secret,
				"LEADER_PUB":  leaderPub,
			},
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	return c
}

// adminBase returns the host-reachable base URL of the leader's admin endpoint.
func adminBase(ctx context.Context, t *testing.T, leader testcontainers.Container) string {
	t.Helper()
	base, err := leader.PortEndpoint(ctx, adminPort+"/tcp", "http")
	require.NoError(t, err)
	return base
}

type adminStatus struct {
	Size int    `json:"size"`
	T    int    `json:"t"`
	Key  string `json:"key"`
}

func getStatus(ctx context.Context, base string) (adminStatus, error) {
	var s adminStatus
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/status", nil)
	if err != nil {
		return s, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s, fmt.Errorf("status %d", resp.StatusCode)
	}
	return s, json.NewDecoder(resp.Body).Decode(&s)
}

// waitStatusSize polls /status until the group reaches want members (tolerating dial
// errors while the admin server is still binding), then returns the status.
func waitStatusSize(ctx context.Context, t *testing.T, base string, want int, timeout time.Duration) adminStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last adminStatus
	for time.Now().Before(deadline) {
		if s, err := getStatus(ctx, base); err == nil {
			last = s
			if s.Size == want {
				return s
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("group never reached size %d within %s (last size %d, t %d, key %q)", want, timeout, last.Size, last.T, last.Key)
	return adminStatus{}
}

// postBan asks the leader to ban the member with the given compressed host pubkey.
func postBan(ctx context.Context, t *testing.T, base, hostpub string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/ban?hostpub="+hostpub, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ban: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// waitLog blocks until substr appears in the container's logs (logs persist after the
// container exits, so this works for the banned follower) or timeout elapses.
func waitLog(ctx context.Context, t *testing.T, c testcontainers.Container, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rc, err := c.Logs(ctx); err == nil {
			b, _ := io.ReadAll(rc)
			rc.Close()
			if bytes.Contains(b, []byte(substr)) {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("log %q not seen within %s", substr, timeout)
}

// hostpubHex derives the compressed host pubkey (hex) from a 32-byte hex host secret,
// matching what a follower sends to the leader in Join.
func hostpubHex(t *testing.T, secretHex string) string {
	t.Helper()
	b, err := hex.DecodeString(secretHex)
	require.NoError(t, err)
	return hex.EncodeToString(secp.PrivKeyFromBytes(b).PubKey().SerializeCompressed())
}

// buildImage compiles the dkgnode harness as a static linux binary and bakes it into
// a scratch image (built once, reused by every container).
func buildImage(ctx context.Context, t *testing.T) {
	t.Helper()

	moduleDir, err := os.Getwd() // `go test` runs in the package (module) directory
	require.NoError(t, err)

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "dkgnode")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", bin, "./cmd/dkgnode")
	build.Dir = moduleDir
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build dkgnode: %v\n%s", err, out)
	}

	dockerfile := "FROM scratch\nCOPY dkgnode /dkgnode\nENTRYPOINT [\"/dkgnode\"]\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "Dockerfile"), []byte(dockerfile), 0o644))

	bc, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:        tmp,
				Dockerfile:     "Dockerfile",
				Repo:           "thresholdsdk-dkgnode",
				Tag:            "itest",
				KeepImage:      true,
				BuildLogWriter: os.Stderr,
			},
		},
		Started: false,
	})
	require.NoError(t, err)
	_ = bc.Terminate(ctx)
}

// extractResult returns the first RESULT= group key in a container's logs.
func extractResult(ctx context.Context, t *testing.T, c testcontainers.Container, re *regexp.Regexp) string {
	t.Helper()
	rc, err := c.Logs(ctx)
	require.NoError(t, err)
	defer rc.Close()
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	m := re.FindSubmatch(b)
	require.NotNilf(t, m, "no RESULT= in logs:\n%s", b)
	return string(m[1])
}
