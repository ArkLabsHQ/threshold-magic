// Command dkgnode is a test-only harness that runs one role of a ChillDKG
// ceremony from environment configuration, for the Docker integration test. It
// is not part of the SDK's public surface and never imports testcontainers.
//
// Env: ROLE (coordinator|participant), LISTEN_ADDR (coordinator, e.g. ":9000"),
// COORD_ADDR (participant, e.g. "coordinator:9000"), HOST_SECRET (participant,
// 32-byte hex), SESSION (the shared session descriptor as JSON).
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	core "github.com/ArkLabsHQ/thresholdmagic/thresholdcore"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	sdk "thresholdsdk"
	itest "thresholdsdkintegration"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("DKG-FAIL", err)
		os.Exit(1)
	}
}

func run() error {
	d, err := itest.ParseSessionDescriptor(os.Getenv("SESSION"))
	if err != nil {
		return fmt.Errorf("parse SESSION: %w", err)
	}
	params, err := d.Params()
	if err != nil {
		return fmt.Errorf("build params: %w", err)
	}
	store, err := sdk.OpenBadgerStore("")
	if err != nil {
		return err
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	switch role := os.Getenv("ROLE"); role {
	case "coordinator":
		c, err := sdk.NewCoordinator(params, os.Getenv("LISTEN_ADDR"), store)
		if err != nil {
			return err
		}
		// Listener is bound by NewCoordinator; the gRPC server starts inside Run,
		// so announce readiness and then drive the ceremony immediately.
		fmt.Println("COORD-LISTENING", c.Addr().String())
		if _, err := c.Run(ctx); err != nil {
			return err
		}
		fmt.Println("COORD-OK")

	case "participant":
		sk, err := sdk.HostKeyFromHex(os.Getenv("HOST_SECRET"))
		if err != nil {
			return err
		}
		p, err := sdk.NewParticipant(params, sk, os.Getenv("COORD_ADDR"), store)
		if err != nil {
			return err
		}
		kp, err := p.Run(ctx)
		if err != nil {
			return err
		}
		fmt.Println("RESULT=" + groupVKHex(kp))
		fmt.Println("DKG-OK")

	default:
		return fmt.Errorf("unknown ROLE %q", role)
	}

	// Stay alive so the test can scrape logs and control teardown.
	select {}
}

// groupVKHex encodes the group verifying key (compressed secp256k1 point) as hex.
// All honest participants derive the same group key, so it is the agreement signal
// (params_id is not — it is input-derived and identical by construction).
func groupVKHex(kp core.KeyPackage) string {
	e := kp.VerifyingKey.E // value copy; safe to normalize in place
	e.ToAffine()
	return hex.EncodeToString(secp.NewPublicKey(&e.X, &e.Y).SerializeCompressed())
}
