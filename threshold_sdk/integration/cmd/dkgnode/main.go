// Command dkgnode is a test-only harness that runs one role of a leader/follower
// ChillDKG group from environment configuration, for the Docker integration test. It
// is not part of the SDK's public surface and never imports testcontainers.
//
// Env: ROLE (leader|follower); HOST_SECRET (both, 32-byte hex); LISTEN_ADDR (leader,
// e.g. ":9000"); COORD_ADDR (follower, e.g. "leader:9000"); LEADER_PUB (follower, hex
// of the leader's 33-byte compressed host pubkey, pinned to verify the leader's
// signed commands).
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	sdk "thresholdsdk"
)

func main() {
	if err := run(); err != nil {
		fmt.Println("DKG-FAIL", err)
		os.Exit(1)
	}
}

func run() error {
	sk, err := sdk.HostKeyFromHex(os.Getenv("HOST_SECRET"))
	if err != nil {
		return fmt.Errorf("HOST_SECRET: %w", err)
	}
	store, err := sdk.OpenBadgerStore("")
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()

	switch role := os.Getenv("ROLE"); role {
	case "leader":
		l, err := sdk.NewLeader(sk, os.Getenv("LISTEN_ADDR"), store)
		if err != nil {
			return err
		}
		fmt.Println("LEADER-LISTENING", l.Addr().String())
		fmt.Println("LEADER-HOSTPUB=" + hex.EncodeToString(sk.PubKey().SerializeCompressed()))
		return l.Serve(ctx) // long-lived: serves the relay + re-DKGs as followers join

	case "follower":
		pkb, err := hex.DecodeString(os.Getenv("LEADER_PUB"))
		if err != nil {
			return fmt.Errorf("LEADER_PUB: %w", err)
		}
		leaderPub, err := secp.ParsePubKey(pkb)
		if err != nil {
			return fmt.Errorf("LEADER_PUB: %w", err)
		}
		f, err := sdk.NewJoiningFollower(sk, os.Getenv("COORD_ADDR"), leaderPub, store)
		if err != nil {
			return err
		}
		// Announce the group key each time this follower obtains a share. All honest
		// members derive the same key, so it is the agreement signal.
		go func() {
			for out := range f.Keys() {
				fmt.Println("DKG-OK RESULT=" + hex.EncodeToString(out.ThresholdPubkey))
			}
		}()
		return f.Serve(ctx) // long-lived: join, then participate in every re-DKG
	default:
		return fmt.Errorf("unknown ROLE %q", role)
	}
}
