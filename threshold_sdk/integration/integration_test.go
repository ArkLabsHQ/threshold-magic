//go:build integration

package thresholdsdkintegration

import (
	"context"
	"encoding/hex"
	"io"
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
	dkgImage     = "thresholdsdk-dkgnode:itest"
	numFollowers = 4
	relayPort    = "9000"
)

// TestDockerLeaderFollowerDKG runs a real leader/follower DKG across containers (1
// leader + N followers) over a Docker network: each follower joins dynamically, the
// leader re-DKGs on every join, and every follower ends up holding a share of the
// same group key (stable because the leader's secret a0 is fixed).
func TestDockerLeaderFollowerDKG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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

	followerSecrets := make([]string, numFollowers)
	for i := range followerSecrets {
		sk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		followerSecrets[i] = hex.EncodeToString(sk.Serialize())
	}

	buildImage(ctx, t)

	net, err := network.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(context.Background()) })

	// Leader: announce readiness via LEADER-LISTENING before followers dial it (gRPC
	// clients connect lazily, so ordering is enough).
	leader, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          dkgImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"leader"}},
			Env: map[string]string{
				"ROLE":        "leader",
				"HOST_SECRET": hex.EncodeToString(leaderSk.Serialize()),
				"LISTEN_ADDR": ":" + relayPort,
			},
			WaitingFor: wait.ForLog("LEADER-LISTENING").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = leader.Terminate(context.Background()) })

	// Followers join dynamically; the leader re-DKGs on each join.
	followers := make([]testcontainers.Container, numFollowers)
	for i := 0; i < numFollowers; i++ {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:    dkgImage,
				Networks: []string{net.Name},
				Env: map[string]string{
					"ROLE":        "follower",
					"COORD_ADDR":  "leader:" + relayPort,
					"HOST_SECRET": followerSecrets[i],
					"LEADER_PUB":  leaderHostpub,
				},
			},
			Started: true,
		})
		require.NoErrorf(t, err, "start follower %d", i)
		followers[i] = c
		t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	}

	// Each follower reaches DKG-OK once it holds a share of the group key.
	for i, c := range followers {
		err := wait.ForLog("DKG-OK").WithStartupTimeout(120 * time.Second).WaitUntilReady(ctx, c)
		require.NoErrorf(t, err, "follower %d did not reach DKG-OK", i)
	}

	// Every follower must report the same compressed group key (a0 is fixed, so the
	// key is stable regardless of join order or committee size).
	re := regexp.MustCompile(`RESULT=([0-9a-fA-F]{66})`)
	var groupKey string
	for i, c := range followers {
		vk := extractResult(ctx, t, c, re)
		require.Truef(t, vk[:2] == "02" || vk[:2] == "03", "follower %d VK not a compressed pubkey: %s", i, vk)
		if i == 0 {
			groupKey = vk
			continue
		}
		require.Equalf(t, groupKey, vk, "follower %d disagrees on the group key", i)
	}

	t.Logf("leader/follower DKG over %d containers succeeded; group key %s", numFollowers+1, groupKey)
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
