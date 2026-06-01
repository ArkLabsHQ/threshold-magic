# threshold-magic — Features

A Go threshold-signature toolkit over secp256k1 (decred `dcrec/secp256k1/v4`):
FROST distributed key generation and signing, plus a **ChillDKG** layer
(encrypted PedPop + a certifying equality check) and a transport-agnostic SDK to
run a full DKG ceremony over any message channel.

## Modules (`go.work` workspace)

| Module | Package | Responsibility |
|---|---|---|
| `threshold_core` | `thresholdcore` | Pure crypto/protocol: PedPop DKG, ChillDKG steps, EncPedPop, CertEq, blame. No I/O. |
| `threshold_frost` | `threshold_signing` | RFC 9591 FROST signing (nonces, binding factors, sign, aggregate, verify). |
| `threshold_chilldkg` | `thresholdchilldkg` | Transport-agnostic SDK: `Transport` interface, in-memory `MemHub`, Participant/Coordinator session drivers. |
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

## 3. Transport-agnostic SDK — `threshold_chilldkg`

- **`Transport` interface** + reference in-memory **`MemHub`** ([transport.go](threshold_chilldkg/transport.go)); messages are `{Type, From, To, Payload}` with hex-identifier addresses; wire codec in [wire.go](threshold_chilldkg/wire.go).
- **`Participant`** ([participant.go](threshold_chilldkg/participant.go)) and **`Coordinator`** ([coordinator.go](threshold_chilldkg/coordinator.go)) drive a full ceremony over the pure step functions: round 1 → cmsg1 broadcast → encrypted round 2 → aggregate → finalize → CertEq.
- **Byzantine-robust collection** — `collectFromAll` counts **distinct, authenticated senders** (membership-filtered, first-message-wins), so a participant flooding duplicates cannot starve another's slot.
- **Investigation round-trip** — a participant whose finalize fails sends `msgInvRequest`; the coordinator replies point-to-point with the per-sender authenticated ciphertexts (`msgInvData`); the failing participant returns the typed culprit error. Other participants receive `msgAbort` and return `ErrCeremonyAborted`. A withheld `msgInvData` is normalized to `FaultyCoordinatorError`.

## 4. Trust model & security properties

- **Output safety** — CertEq guarantees all honest parties agree on the same group key, even with a malicious coordinator (it cannot collect N signatures on divergent transcripts).
- **Share secrecy** — additive pads make round-2 ciphertexts information-theoretically masked from everyone but the intended recipient (and the coordinator that only sees sums).
- **Blame soundness** — round-2 signatures + CertEq root attribution in the host keys; a malicious coordinator that alters/withholds a share is itself blamed, never an honest sender. (One residual: a coordinator that *equivocates* the round-1 broadcast `cmsg1` on an unauthenticated network transport — see deferred items. `MemHub` broadcasts consistently, so this is not expressible there.)
- **Liveness** — abort is always possible for any participant (withholding); the protocol provides *identifiable* abort (who to exclude on retry), not guaranteed completion.

## 5. Deferred / out of scope

- **`cmsg1`-equivocation binding** (e.g. an `eq_input` comparison step) for full blame soundness on an adversarial *network* transport.
- **Automated retry** excluding an identified culprit (identifiable-abort → re-run).
- **Share recovery** from `RecoveryData` (currently transcript + certificate only) and a canonical `RecoveryData` serialization.
- A first-class **network transport adapter** (the SDK is transport-agnostic; only the in-memory `MemHub` ships here).

## 6. Tests

- `threshold_core`: PedPop dealer DKG; ChillDKG end-to-end (reconstruct == Σ secrets, group-key agreement, certificate verify); pad round-trip; eq_input determinism/tamper; CertEq equivocation; blame attribution (faulty sender, coordinator share-tamper, self-tamper, aggregate mismatch, infinity-neutral, deterministic culprit); `PartialCiphertextsFor`.
- `threshold_frost`: FROST sign+aggregate over ChillDKG-produced keys.
- `threshold_chilldkg`: full session over `MemHub`; coordinator-share-tamper ⇒ coordinator blamed (honest sender not framed); withheld investigation data ⇒ coordinator blamed; duplicate-flood ⇒ deduped and ceremony succeeds.

Run: `cd threshold-magic && for m in threshold_core threshold_frost threshold_chilldkg; do go test -C $m ./...; done`
