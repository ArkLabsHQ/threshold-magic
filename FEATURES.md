# threshold-magic — Features

A Go threshold-signature toolkit over secp256k1 (decred `dcrec/secp256k1/v4`):
FROST distributed key generation and signing, plus a **ChillDKG** layer
(encrypted PedPop + a certifying equality check), a transport-agnostic SDK to
run a full DKG ceremony over any message channel, and an embeddable SDK wiring the
gRPC transport with BadgerDB persistence.

## Modules (`go.work` workspace)

| Module | Package | Responsibility |
|---|---|---|
| `threshold_core` | `thresholdcore` | Pure crypto/protocol: PedPop DKG, ChillDKG steps, EncPedPop, CertEq, blame. No I/O. |
| `threshold_frost` | `threshold_signing` | RFC 9591 FROST signing (nonces, binding factors, sign, aggregate, verify). |
| `threshold_chilldkg` | `thresholdchilldkg` | Transport-agnostic SDK: `Transport` interface, in-memory `MemHub`, Participant/Coordinator session drivers. |
| `threshold_chilldkg/grpc` | `chillgrpc` | gRPC `Transport` adapter (insecure): coordinator relay `Server` + participant `Client`. Own module to isolate grpc/protobuf deps. |
| `threshold_sdk` | `thresholdsdk` | Embeddable SDK: wires the gRPC transport + ChillDKG drivers + BadgerDB persistence behind a small programmatic API (host secret as a parameter, injectable `Store`). Own module to isolate the BadgerDB dependency. |
| `threshold_nostrdkg` | `thresholdnostrdkg` | Legacy Nostr-transport DKG driver (independent; not part of the ChillDKG SDK). |

---

## 1. Base DKG & signing (pre-existing)

- **Pedersen DKG with Feldman VSS** — `DKGPart1/2/3` in [threshold_core/dkg.go](threshold_core/dkg.go): polynomial commitments φ, per-participant Schnorr proof-of-knowledge, share verification against commitments, `KeyPackage`/`PublicKeyPackage` outputs.
- **Refresh / re-share** — `DKGRefreshPart1/2/3` (group key unchanged, shares rotated).
- **Secret reconstruction** — `Reconstruct` (Lagrange at 0) in [threshold_core/share.go](threshold_core/share.go).
- **FROST signing** — RFC 9591 in `threshold_frost/src`: `NewNonce`, `Sign`, `Aggregate`, `VerifySignatureShare`, cheater detection.

## 2. ChillDKG (this work)

Brings the semantics of BlockstreamResearch/bip-frost-dkg into the library in
**hybrid** form — faithful EncPedPop + CertEq construction, reusing the existing
secp256k1 / identifier / commitment primitives (not byte-for-byte BIP-wire compatible).

### 2.1 Encrypted PedPop (EncPedPop) — [threshold_core/encpedpop.go](threshold_core/encpedpop.go)
- Each secret share is masked with an **additive ECDH pad**: `ciphertext = f_i(ℓ) + pad_iℓ (mod n)`, so shares are safe over any channel (secrecy is in the protocol, not the transport).
- Pads use **ephemeral-static ECDH**: a fresh per-session ephemeral key on the sender side, the long-lived host key on the recipient side (`ecdhPadSend`/`ecdhPadRecv`); a keyed-hash `selfPad` for the self share.
- Because masking is additive, the **coordinator aggregates** ciphertexts per recipient (`AggregateCiphertexts`) without learning anything; the recipient subtracts the pads and verifies `g^{s_ℓ}` against the **summed** VSS commitment (`DecryptAndVerifyShare`), rejecting a point-at-infinity group key.

### 2.2 Deterministic session id (`params_id`) — [threshold_core/chilldkg.go](threshold_core/chilldkg.go)
- No random session nonce. `SessionID` is a tagged hash committing to `T`, `N`, and every `(identifier, host key)` pair (`ParamsID`), so all parties derive it identically with no coordination, and it doubles as an out-of-band agreement check.
- `NewSessionParams(t, hostPubs)` constructs it; `Validate()` rejects any params whose `SessionID` ≠ the derived `params_id`. Participant order is derived on demand (`IDs()`), never stored.
- Per-session freshness/anti-replay comes from the **fresh ephemeral key bound into every pad**, not from a nonce.

### 2.3 Round-2 share authentication — [threshold_core/encpedpop.go](threshold_core/encpedpop.go)
- Each sender **BIP340-signs every round-2 entry** `(sessionID, sender, recipient, ephPub, ciphertext)` under its host key (`SignRound2Share`); the ciphertext+signature travel together as an `AuthenticatedShare`.
- This roots blame in the **host keys** (the trust anchor agreed via `params_id`), independent of the untrusted coordinator: a coordinator that alters a relayed ciphertext cannot forge the sender's signature.

### 2.4 CertEq — certifying equality check — [threshold_core/certeq.go](threshold_core/certeq.go)
- Each participant BIP340-signs the **transcript hash** `eq_input` under its host key; collecting `N` valid signatures on the same `eq_input` is a **success certificate** proving every honest party computed the identical transcript — defeating an equivocating coordinator.
- The transcript is a **canonical, fixed-width, sorted** byte string (never JSON; documented byte layout in `serializeTranscript`): sessionID, T, N, sorted host identities, per-participant (VSS commitment + PoK + ephemeral key), and the group commitment/key.
- `BuildEqInput`, `CertEqSign`, `CertEqVerifyAll`.

### 2.5 Blame / investigation sub-protocol — [threshold_core/investigate.go](threshold_core/investigate.go)
When a recipient's aggregate share fails to verify, attribution recovers *who* is at fault (the aggregation otherwise hides it):
- The coordinator reveals the per-sender authenticated ciphertexts addressed to that recipient (`PartialCiphertextsFor`).
- `InvestigateShare` runs, in order: **(0)** infinity-key guard (returns `ErrInfinityVerifyingKey` — blames no one); **(1)** verify each sender's round-2 signature — a missing/invalid signature ⇒ `FaultyCoordinatorError` (it tampered or withheld; cannot forge); **(2)** the authenticated parts must sum to the handed aggregate ⇒ else `FaultyCoordinatorError`; **(3)** per-sender check `g^{f_i(ℓ)} == φ_i.GetVerifyingShare(ℓ)` in sorted order — a signed-but-inconsistent share ⇒ `FaultyParticipantError{Culprit}` (deterministic, lowest id).
- **Soundness principle:** a participant is blamed only on cryptographic proof (a validly signed, inconsistent share); ambiguous failures fall to the coordinator, so an honest sender is never framed.

### 2.6 Share recovery & canonical RecoveryData — [threshold_core/recovery.go](threshold_core/recovery.go)
- `RecoveryData` is a single **shared, public blob** (identical for all participants): session params, round-1 contributions, ephemeral keys, the aggregated per-recipient encrypted shares, and the success certificate. It holds no secrets — the encrypted shares are additively masked from non-recipients.
- `RecoverShare(rd, hostSk)` lets any member recompute its own `DKGOutput` from **just its host secret key + the blob** — no identifier need be remembered: the caller's identifier is found by matching its host public key in the blob (host keys are unique, enforced by `Validate`). It verifies the certificate, then reuses `DecryptAndVerifyShare` (which re-checks the result against the certified group commitment, so a tampered share errors rather than returning a wrong one). This mirrors the BIP's `recover(hostseckey, recovery_data)`, which finds your index by host-pubkey lookup.
- `Verify()` re-derives the transcript from the structured fields and checks the full N-of-N certificate; `Serialize()`/`ParseRecoveryData` give a **canonical, deterministic** encoding (hex-keyed JSON; `SessionID` re-derived on parse, never trusted) so every party produces byte-identical blobs.
- The coordinator broadcasts all aggregated shares (`msgEncShares`) so every participant can populate the shared blob, and `Coordinator.Run` itself returns the same canonical `RecoveryData` (verified before the certificate is broadcast) so the coordinator can serve it to a returning member.

## 3. Transport-agnostic SDK — `threshold_chilldkg`

- **`Transport` interface** + reference in-memory **`MemHub`** ([transport.go](threshold_chilldkg/transport.go)); messages are `{Type, From, To, Payload}` with hex-identifier addresses; wire codec in [wire.go](threshold_chilldkg/wire.go).
- **`Participant`** ([participant.go](threshold_chilldkg/participant.go)) and **`Coordinator`** ([coordinator.go](threshold_chilldkg/coordinator.go)) drive a full ceremony over the pure step functions: round 1 → cmsg1 broadcast → encrypted round 2 → aggregate → finalize → CertEq. Both `Run` methods return the `RecoveryData` blob (the coordinator so it can serve it; participants for their own backup).
- **Byzantine-robust collection** — `collectFromAll` counts **distinct, authenticated senders** (membership-filtered, first-message-wins), so a participant flooding duplicates cannot starve another's slot.
- **Investigation round-trip** — a participant whose finalize fails sends `msgInvRequest`; the coordinator replies point-to-point with the per-sender authenticated ciphertexts (`msgInvData`); the failing participant returns the typed culprit error. Other participants receive `msgAbort` and return `ErrCeremonyAborted`. A withheld `msgInvData` is normalized to `FaultyCoordinatorError`.
- **gRPC transport** (separate module `thresholdchilldkggrpc`, [threshold_chilldkg/grpc](threshold_chilldkg/grpc)) — a real network `Transport` matching the star topology: the coordinator runs a gRPC relay (`Server`), each participant a `Client` that sends via a unary `Send` and receives via a server-streaming `Subscribe`. Faithfully reproduces `MemHub` semantics (the `Server` pre-creates a buffered queue per participant so a broadcast is held for a not-yet-subscribed member). **Insecure (no TLS) for now**; kept in its own module so grpc/protobuf deps stay out of the core SDK.
- **Embeddable SDK** (separate module `thresholdsdk`, [threshold_sdk](threshold_sdk)) — packages running a ceremony behind a small, programmatic API (no env vars, no config files, no daemon). `NewCoordinator(params, listenAddr, store)` runs the relay and persists the blob; `NewParticipant(params, hostSk, coordinatorAddr, store)` finds its own identifier by host-pubkey match, generates fresh per-run contribution randomness, runs the DKG over gRPC, and persists. Persistence goes through an **injectable `Store`** (BadgerDB implementation provided, in-memory for tests) and holds **only the public `RecoveryData` blob — no secret at rest**: `LoadKeyPackage` reconstructs the key package on demand via `RecoverShare` (host key + blob), which re-verifies the success certificate and re-checks the share against the certified commitment. `Run` is idempotent per `params_id`.

## 4. Trust model & security properties

- **Output safety** — CertEq guarantees all honest parties agree on the same group key, even with a malicious coordinator (it cannot collect N signatures on divergent transcripts).
- **Share secrecy** — additive pads make round-2 ciphertexts information-theoretically masked from everyone but the intended recipient (and the coordinator that only sees sums).
- **Blame soundness** — round-2 signatures + CertEq root attribution in the host keys; a malicious coordinator that alters/withholds a share is itself blamed, never an honest sender. (One residual: a coordinator that *equivocates* the round-1 broadcast `cmsg1` on an unauthenticated network transport — see deferred items. `MemHub` broadcasts consistently, so this is not expressible there.)
- **Liveness** — abort is always possible for any participant (withholding); the protocol provides *identifiable* abort (who to exclude on retry), not guaranteed completion.
- **Recoverability** — the public `RecoveryData` blob lets any member recover its `DKGOutput` from a backup + its host key, and convinces a latecomer of the result via the success certificate (§2.6).

## 5. Deferred / out of scope

- **`cmsg1`-equivocation binding** (e.g. an `eq_input` comparison step) for full blame soundness on an adversarial *network* transport.
- **Automated retry** excluding an identified culprit (identifiable-abort → re-run).
- **TLS/mTLS + auth for the gRPC transport** (it ships **insecure** today); plus reconnect/resilience for the participant stream.

## 6. Tests

- `threshold_core`: PedPop dealer DKG; ChillDKG end-to-end (reconstruct == Σ secrets, group-key agreement, certificate verify); pad round-trip; eq_input determinism/tamper; CertEq equivocation; blame attribution (faulty sender, coordinator share-tamper, self-tamper, aggregate mismatch, infinity-neutral, deterministic culprit); `PartialCiphertextsFor`; recovery (RecoverShare reproduces each KeyPackage from host key alone, canonical Serialize/Parse round-trip, tampered-share error, foreign/nil host-key guards, tampered-cert rejection).
- `threshold_frost`: FROST sign+aggregate over ChillDKG-produced keys.
- `threshold_chilldkg`: full session over `MemHub`; coordinator-share-tamper ⇒ coordinator blamed (honest sender not framed); withheld investigation data ⇒ coordinator blamed; duplicate-flood ⇒ deduped and ceremony succeeds; recovery (all participants' blobs byte-identical, round-trip, `RecoverShare` reproduces each key).
- `thresholdchilldkggrpc`: full DKG end-to-end over a real gRPC listener (2-of-3, 3-of-5) with blobs byte-identical to the coordinator's and `RecoverShare` reproducing each key; late subscriber still succeeds (pre-created buffers); missing participant times out cleanly; server admission guards (empty/unknown addr, empty To).
- `thresholdsdk`: full ceremony over a real gRPC listener with BadgerDB stores (2-of-3, 3-of-5) — every participant's stored blob byte-identical to the coordinator's, and `LoadKeyPackage`/`RecoverShare` reproduce each share from the blob + host key; host key absent from params ⇒ `ErrSelfNotInParams`; `HostKeyFromHex` length/zero guards; idempotent re-run; missing participant times out cleanly with nothing persisted.

Run: `cd threshold-magic && for m in threshold_core threshold_frost threshold_chilldkg threshold_chilldkg/grpc threshold_sdk; do go test -C $m ./...; done`
