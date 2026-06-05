# threshold-magic

A Go threshold-signature toolkit over secp256k1 (decred `dcrec/secp256k1/v4`): FROST
distributed key generation and signing, a **ChillDKG** layer (BIP-FROST-DKG: encrypted
PedPop + a certifying equality check) verified **byte-exact against all 51 upstream
test vectors**, and an embeddable **leader / follower** DKG SDK over gRPC with dynamic
membership.

## Modules (`go.work` workspace)

| Module | Package | Responsibility |
|---|---|---|
| `threshold_core` | `thresholdcore` | Pure crypto/protocol: PedPop DKG, the byte-exact `BIP*` ChillDKG steps, EncPedPop, CertEq, blame. No I/O. |
| `threshold_frost` | `threshold_signing` | RFC 9591 FROST signing (nonces, binding factors, sign, aggregate, verify). |
| `threshold_sdk` | `thresholdsdk` | Embeddable **leader/follower** DKG SDK: drives the BIP path over a gRPC relay with BadgerDB persistence. |
| `threshold_sdk/integration` | `thresholdsdkintegration` | Docker-based integration test (testcontainers) + the env-driven `cmd/dkgnode` harness it runs in containers. `integration` build tag keeps Docker out of the default sweep. |
| `threshold_nostrdkg` | `thresholdnostrdkg` | Legacy Nostr-transport DKG driver (independent; not part of the SDK). |

The ChillDKG crypto internals (EncPedPop pads, CertEq, deterministic `params_id`,
recovery) are documented in [FEATURES.md](FEATURES.md) §2.

## Leader / Follower DKG (`threshold_sdk`)

A threshold construction where one **leader** owns the group secret and is designed to
run inside a **secure enclave** (a TEE / confidential-computing environment), so that
secret is hardware-isolated from the host OS and operator — never held by a person.
Built on the byte-exact BIP path:

- **One leader, many followers.** The leader is *both* coordinator and a participant
  and is the only party that contributes the secret constant term `a0`. Every follower
  contributes the **identity element** (`a0 = 0`, i.e. the point at infinity `O = g⁰`,
  with no proof-of-possession). So the aggregate secret is just the leader's `a0` and
  the group key is `g^(a0)` (with the deterministic BIP taproot tweak).
- **`a0` is generated once and persisted.** It is membership-independent, so the group
  public key is **stable across every membership change** — only the committee,
  threshold, and shares move.
- **Dynamic membership.** A follower joins via the `Join` RPC (proving possession of
  its host key); the leader can `Ban` a member. Each change triggers a **re-DKG that
  reuses the same `a0`**, asserts the key did not drift, then persists.
- **Majority threshold.** `t = ⌊n/2⌋ + 1` over the current members (`n = leader +
  followers`), recomputed per re-DKG ([`MajorityPolicy`](threshold_sdk/policy.go)).
- **Authenticated commands.** Leader rekey/removed commands are BIP340-signed by the
  leader's host key over a tagged hash with a monotonic epoch (anti-replay); followers
  pin the leader key and verify before acting. The gRPC relay itself is untrusted.
- **Leadership is not in the wire params.** It is threaded as an explicit `leader
  *Identifier` argument to the `BIP*` functions, so `params_id` stays standard BIP and
  the **51/51 vectors remain byte-exact** when no leader is set.

```go
// Leader: enclave-resident owner; serves the relay and re-DKGs as members come and go.
l, _ := sdk.NewLeader(hostSk, ":9000", store)
go l.Serve(ctx)
l.Ban(ctx, victimHostPub)        // evict a member -> survivors re-key, key unchanged
key, _ := l.Pubkey()             // stable group key
n, t := l.GroupSize(), l.Threshold()

// Follower: contributes the identity element; joins and rides every re-DKG.
f, _ := sdk.NewJoiningFollower(hostSk, "leader:9000", leaderPub, store)
go f.Serve(ctx)
for out := range f.Keys() { /* holds a share of out.ThresholdPubkey */ }
```

**Trust model.** The leader's *process* holds the full group secret `a0` by
construction, so it is meant to run inside a **secure enclave**: the enclave isolates
`a0` from the host OS and operator, so the trust anchor is the attested enclave, not a
custodian. The followers' threshold shares are defense-in-depth and recovery, not a
constraint on the leader. The gRPC transport is **insecure (no TLS)** today; end-to-end
command authentication (BIP340-signed, epoch-bound) is independent of it.

## Integration test (`threshold_sdk/integration`)

`TestDockerLeaderFollowerDKG` runs a **real distributed** leader/follower group across
Docker containers (testcontainers), driving one long-lived leader through a full
membership ramp and asserting the invariants at every step:

- **Joins** — five followers join one at a time. After each, the test reads the
  leader's `/status` (a test-only admin endpoint on the harness) and asserts the group
  size, that the threshold equals an independently-computed majority, that the late
  joiner derived the group key, and that the key never moved.
- **Bans** — the leader bans three members in turn (via `POST /ban`). Each victim exits
  with `ErrRemoved`, the survivors re-key, and the key still does not move.

Because `/status` only advances after a re-DKG fully succeeds, the observed
`(size, threshold)` sequence is itself proof each transition completed:

| | n (leader+followers) | t = ⌊n/2⌋+1 |
|---|---|---|
| join 1…5 | 2, 3, 4, 5, 6 | **2, 2, 3, 3, 4** |
| ban ×3 | 5, 4, 3 | **3, 3, 2** |

The group public key is byte-identical across all eight re-DKGs.

Run it (requires Docker; skipped cleanly if unavailable):

```sh
go test -C threshold_sdk/integration -tags integration -run TestDockerLeaderFollowerDKG -timeout 8m -v
```

## Building & testing

```sh
# Unit tests + the 51 BIP-FROST-DKG vectors (no Docker needed):
go test -C threshold_core ./...          # includes bip_vectors_test.go (51/51)
go test -C threshold_sdk -race ./...     # leader/follower SDK, race-clean

# Everything builds across the workspace:
for m in threshold_core threshold_frost threshold_nostrdkg threshold_sdk threshold_sdk/integration; do
  go build -C "$m" ./...
done
```
