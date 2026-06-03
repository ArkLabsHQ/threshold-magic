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

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	dkgImage  = "thresholdsdk-dkgnode:itest"
	numParts  = 4
	threshold = 3
	relayPort = "9000"
)

// TestDockerDistributedDKG runs a real DKG across 5 containers (1 coordinator +
// 4 participants) over a Docker network and asserts every participant completes
// and agrees on the same group key.
func TestDockerDistributedDKG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Skip cleanly when Docker is unavailable (the build tag already keeps this
	// out of the default test sweep).
	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	if err := provider.Health(ctx); err != nil {
		t.Skipf("docker daemon not healthy: %v", err)
	}

	// Fixture: N host keypairs + identifiers, assembled into the shared descriptor.
	hostSecrets := make([]string, numParts)
	d := SessionDescriptor{Threshold: threshold}
	for i := 0; i < numParts; i++ {
		id, err := core.IdentifierFromUint16(uint16(i + 1))
		require.NoError(t, err)
		sk, err := secp.GeneratePrivateKey()
		require.NoError(t, err)
		hostSecrets[i] = hex.EncodeToString(sk.Serialize())
		d.Participants = append(d.Participants, ParticipantDescriptor{
			ID:         hex.EncodeToString(id.Serialize()),
			HostPubkey: hex.EncodeToString(sk.PubKey().SerializeCompressed()),
		})
	}
	sessionJSON, err := d.Marshal()
	require.NoError(t, err)

	buildImage(ctx, t)

	net, err := network.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(context.Background()) })

	// Coordinator: announce readiness via the COORD-LISTENING log before
	// participants dial it (grpc clients connect lazily, so ordering is enough).
	coord, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          dkgImage,
			Networks:       []string{net.Name},
			NetworkAliases: map[string][]string{net.Name: {"coordinator"}},
			Env: map[string]string{
				"ROLE":        "coordinator",
				"LISTEN_ADDR": ":" + relayPort,
				"SESSION":     sessionJSON,
			},
			WaitingFor: wait.ForLog("COORD-LISTENING").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = coord.Terminate(context.Background()) })

	// Launch all participants first; the ceremony needs all N present, so waiting
	// on one before starting the rest would deadlock.
	parts := make([]testcontainers.Container, numParts)
	for i := 0; i < numParts; i++ {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:    dkgImage,
				Networks: []string{net.Name},
				Env: map[string]string{
					"ROLE":        "participant",
					"COORD_ADDR":  "coordinator:" + relayPort,
					"HOST_SECRET": hostSecrets[i],
					"SESSION":     sessionJSON,
				},
			},
			Started: true,
		})
		require.NoErrorf(t, err, "start participant %d", i)
		parts[i] = c
		t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	}

	// Now wait for each participant to reach DKG-OK.
	for i, c := range parts {
		err := wait.ForLog("DKG-OK").WithStartupTimeout(90 * time.Second).WaitUntilReady(ctx, c)
		require.NoErrorf(t, err, "participant %d did not reach DKG-OK", i)
	}

	// Every participant must report the same compressed group key.
	re := regexp.MustCompile(`RESULT=([0-9a-fA-F]{66})`)
	var groupKey string
	for i, c := range parts {
		vk := extractResult(ctx, t, c, re)
		require.Truef(t, vk[:2] == "02" || vk[:2] == "03", "participant %d VK not a compressed pubkey: %s", i, vk)
		if i == 0 {
			groupKey = vk
			continue
		}
		require.Equalf(t, groupKey, vk, "participant %d disagrees on the group key", i)
	}

	// Coordinator drove the ceremony to completion.
	err = wait.ForLog("COORD-OK").WithStartupTimeout(30 * time.Second).WaitUntilReady(ctx, coord)
	require.NoError(t, err, "coordinator did not reach COORD-OK")

	t.Logf("distributed DKG over %d containers succeeded; group key %s", numParts+1, groupKey)
}

// buildImage compiles the dkgnode harness as a static linux binary and bakes it
// into a scratch image (built once, reused by every container).
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

	// Started:false builds the image (and creates an unstarted container we drop);
	// KeepImage keeps the tag for the real containers to reference by Image name.
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
