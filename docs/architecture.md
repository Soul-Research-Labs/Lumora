# Lumora Architecture

## Overview

Lumora is a zero-knowledge privacy coprocessor for Bitcoin rollups (Strata).
It enables private transfers and withdrawals using Halo2 proofs with the IPA
commitment scheme over the Pallas/Vesta curve cycle.

Key design principles:

- **Transparent setup** — IPA commitments require no trusted ceremony.
- **Domain-separated nullifiers** — Prevents cross-chain replay attacks.
- **Epoch-based finality** — Batches are accumulated into finalized epochs for efficient cross-chain sync.
- **Stealth addresses** — ECDH one-time keys for receiver privacy.
- **Crash-safe persistence** — WAL + periodic snapshots with HMAC integrity.

## System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                      External Clients                                │
│  lumora-cli (REPL)   lumora-sdk (Rust)   @lumora/sdk (TypeScript)   │
│  lumora-client (HTTP)                                                │
└─────────────────────────────┬────────────────────────────────────────┘
                              │  HTTP/JSON (/v1/*)
┌─────────────────────────────▼────────────────────────────────────────┐
│                      RPC Server (lumora-rpc)                          │
│  axum 0.8 · tokio · Arc<RwLock<LumoraNode>>                         │
│  API-key auth · semaphore · relay jitter · Prometheus metrics        │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │ Background Tasks                                              │    │
│  │  batch_poll_loop (5 s)  ─── BatchAccumulator ─── commitment  │    │
│  │  epoch_finalize_loop (60 s) ── EpochManager ── finalized     │    │
│  │                                                   epochs      │    │
│  └──────────────────────────────────────────────────────────────┘    │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│                    Node Daemon (lumora-node)                          │
│  LumoraNode: pool state + prover params + note store                 │
│  Mempool · PeerRegistry · SyncProtocol · ByzantineDetector           │
│  BatchAccumulator · EpochManager · RollupBridge · StealthScanner    │
└────┬─────────┬──────────┬────────────────────────────────────────────┘
     │         │          │
     ▼         ▼          ▼
┌─────────┐ ┌──────────┐ ┌──────────────┐
│Contracts│ │  Prover  │ │   Verifier   │
│pool mgmt│ │proof gen │ │proof verify  │
│WAL/snap │ │parallel  │ │batch verify  │
│epochs   │ │pipeline  │ │versioned VKs │
│events   │ │envelopes │ │              │
└────┬────┘ └────┬─────┘ └──────┬───────┘
     │           │               │
     ▼           ▼               ▼
┌─────────┐ ┌──────────────────────────────┐
│Circuits │ │ Primitives · Note · Tree     │
│transfer │ │ Poseidon · Pallas · IncrMT   │
│withdraw │ │ domain nullifiers · envelopes│
│         │ │ keys · stealth · BIP39       │
└─────────┘ └──────────────────────────────┘
```

## Crate Responsibilities

| Crate               | Role                                                                                                                                                                   |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lumora-primitives` | Poseidon hash, field utilities, domain-separated nullifiers (V2), fixed-size proof envelopes, serde helpers                                                            |
| `lumora-note`       | Note model, spending/viewing keys, ECIES encryption, BIP39 mnemonics, stealth addresses (ECDH one-time keys)                                                           |
| `lumora-tree`       | Depth-32 incremental Merkle tree with append and pruning                                                                                                               |
| `lumora-circuits`   | Halo2 transfer and withdraw circuits, constraint definitions, domain-aware witness inputs                                                                              |
| `lumora-prover`     | Proof generation engine, parallel proving, proof pipeline, proof envelope wrapping                                                                                     |
| `lumora-verifier`   | Proof verification, batch verification, versioned verifier sets                                                                                                        |
| `lumora-contracts`  | Privacy pool state, deposit/transfer/withdraw logic, WAL, snapshots, events, compliance, governance, incentives, epoch management                                      |
| `lumora-node`       | Node daemon, mempool, peer registry, sync protocol, Byzantine detection, batch accumulator, cross-chain bridge/rollup sync                                             |
| `lumora-client`     | HTTP client for the RPC API                                                                                                                                            |
| `lumora-sdk`        | High-level SDK: wallets, transaction history, note management, stealth sends                                                                                           |
| `lumora-cli`        | Interactive REPL with wallet encryption and key management                                                                                                             |
| `lumora-rpc`        | Axum HTTP server, route handlers, relay jitter middleware, background tasks (batch/epoch loops), stealth-scan, epoch-roots                                             |
| `lumora-bitvm`      | BitVM2 bridge: `BitvmBridge` (operator withdrawals, state root commits), `BitvmVerifier` (optimistic verification), challenger, 14 adapters (13 Bitcoin L2 production + EMVCo QR alpha) |

## Data Flow: Private Transfer

```
User ──► SDK/CLI ──► POST /v1/transfer ──► RPC Server ──► LumoraNode
                                                              │
                      ┌───────────────────────────────────────┘
                      ▼
                Build circuit (input notes + Merkle paths + output notes)
                      │
                      ▼
                Prover generates Halo2 proof (3–6 s, K=13)
                      │
                      ▼
                Verifier checks proof against VK
                      │
                      ▼
                Contract logic:
                  1. Validate nullifiers (domain-separated, V2)
                  2. Append output commitments to Merkle tree
                  3. Post encrypted notes to note store
                  4. Emit Transfer event + WAL log
                      │
                      ▼
                BatchAccumulator collects commitment (every 5 s)
                      │
                      ▼
                EpochManager finalizes epoch root (every 60 s)
                      │
                      ▼
                Epoch root available via /v1/epoch-roots for cross-chain sync
```

1. User constructs a transfer request via SDK/CLI.
2. SDK calls the node's `/v1/transfer` RPC endpoint.
3. Node builds the Halo2 circuit with input notes (spending keys, Merkle paths) and output notes.
4. Prover generates a proof (3–6 seconds, K=13), wraps it in a fixed-size proof envelope.
5. Verifier checks the proof against the verifying key.
6. Contract logic validates domain-separated nullifiers, updates the Merkle tree, and emits a `Transfer` event.
7. WAL logs the event; snapshot manager periodically persists full state.
8. Encrypted notes are relayed to recipients via the note store.
9. BatchAccumulator collects the new commitment; EpochManager finalizes epochs for cross-chain sync.

## Data Flow: Stealth Address Transfer

```
Sender                          Recipient
  │                                  │
  │  1. Fetch recipient's           │
  │     stealth meta-address         │
  │     (spend_pk, view_pk)          │
  │                                  │
  │  2. Generate ephemeral keypair   │
  │     r ← random scalar           │
  │     R = r·G                      │
  │                                  │
  │  3. Derive shared secret         │
  │     S = r · view_pk              │
  │     one_time_addr = spend_pk + H(S)·G
  │                                  │
  │  4. Create note committed to     │
  │     one_time_addr, include R     │
  │     in encrypted note payload    │
  │                                  │
  │  ───── POST /v1/transfer ──────► │
  │                                  │
  │                    5. Recipient scans via
  │                       POST /v1/stealth-scan
  │                       Downloads notes in range
  │                                  │
  │                    6. For each note:
  │                       S' = view_sk · R
  │                       one_time_addr' = spend_pk + H(S')·G
  │                       If match → can spend with
  │                       spend_sk + H(S')
```

See [Stealth Addresses](stealth-addresses.md) for full protocol details.

## Batch Accumulator & Epoch Manager

Lumora uses a two-tier batching system for cross-chain compatibility:

### BatchAccumulator

- Runs every **5 seconds** in a background task (`batch_poll_loop`).
- Collects new note commitments appended since the last poll.
- Computes a batch root (Poseidon hash of collected commitments).
- Stores batch roots for later epoch finalization.

### EpochManager

- Runs every **60 seconds** in a background task (`epoch_finalize_loop`).
- Aggregates all batch roots since the last finalized epoch.
- Computes an **epoch root** (Poseidon hash of batch roots).
- Assigns a monotonically increasing `epoch_id`.
- Finalized epoch roots are served via `GET /v1/epoch-roots`.

```
Commitments ──► BatchAccumulator (5s) ──► Batch roots
                                              │
               EpochManager (60s) ◄───────────┘
                    │
                    ▼
              Epoch root + epoch_id ──► /v1/epoch-roots
                    │
                    ▼
              Cross-chain verifiers (Strata L1, other rollups)
```

See [Cross-Chain Privacy](cross-chain-privacy.md) for domain separation and sync details.

## State Model

The privacy pool state consists of:

- **Merkle tree**: Depth-32 incremental tree holding note commitments.
- **Nullifier set**: Set of spent nullifiers (constant-time lookup). Domain-separated V2 format prevents cross-chain replay.
- **Root history**: Last 256 Merkle roots for stale-proof tolerance.
- **Pool balance**: Total deposited value minus withdrawals.
- **Event log**: Ordered sequence of Deposit/Transfer/Withdraw events.
- **Batch roots**: Uncommitted batch roots pending epoch finalization.
- **Epoch history**: Finalized epoch roots with `epoch_id` and timestamp.

State is persisted via:

- **WAL** (`wal.log`): Append-only, fsync'd, crash-safe log.
- **Snapshots** (`snapshot_NNNNNN.bin`): Periodic binary snapshots with HMAC integrity.
- See [State Persistence](state-persistence.md) for details.

## Network Layer

Nodes communicate via:

- **State deltas**: Signed with HMAC-SHA256, contain events + height.
- **Mempool sync**: Digest comparison + batch exchange.
- **Transaction broadcast**: HMAC-authenticated event propagation.
- **Heartbeat**: Periodic liveness pings between peers.
- **Byzantine detection**: Equivocation and root mismatch detection.
- **Partition recovery**: Automatic diagnosis and catch-up plans.
- **Cross-chain sync**: Epoch roots pushed/pulled between rollup bridges.

## Security Layers

| Layer             | Mechanism                                                                                             |
| ----------------- | ----------------------------------------------------------------------------------------------------- |
| Proof system      | Halo2 IPA, transparent SRS, no trusted setup                                                          |
| Note privacy      | ECIES encryption (ChaCha20-Poly1305), viewing key separation                                          |
| Stealth addresses | ECDH one-time keys, unlinkable payments                                                               |
| Nullifier privacy | Domain-separated V2 nullifiers, cross-chain replay prevention                                         |
| State integrity   | HMAC-SHA256 on persisted state and deltas                                                             |
| API security      | API key authentication, rate limiting, body size limits                                               |
| Relay privacy     | Configurable jitter (50–500 ms) to prevent timing correlation                                         |
| Wallet security   | AES-256-GCM encryption, Argon2 key derivation                                                         |
| Compliance        | Pluggable oracle interface for KYC/AML                                                                |
| Proof envelopes   | Fixed-size padding prevents proof-size side channels                                                  |
| BitVM2 bridge     | Optimistic verification on Bitcoin L1; bonded assertions with challenge-response and timeout finality |

## Related Documents

- [Getting Started](getting-started.md) — Build and run instructions
- [Cryptography](cryptography.md) — Cryptographic primitives and constructions
- [Circuit Constraints](circuit-constraints.md) — ZK circuit details
- [Cross-Chain Privacy](cross-chain-privacy.md) — Domain-separated nullifiers and epoch sync
- [Stealth Addresses](stealth-addresses.md) — ECDH one-time address protocol
- [State Persistence](state-persistence.md) — WAL, snapshots, recovery
- [Light Client Design](light-client-design.md) — Light client protocol
- [EMV Bridge Integration](emv-bridge.md) — EMVCo QR adapter contract and mapping details
- [Protocol Specification](../PROTOCOL.md) — Formal protocol spec
- [Threat Model](../THREAT_MODEL.md) — Attack surface analysis
