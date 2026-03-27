# Lumora

[![CI](https://github.com/lumora/lumora/actions/workflows/ci.yml/badge.svg)](https://github.com/lumora/lumora/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

**Privacy coprocessor for Bitcoin rollups** — zero-knowledge private transfers on [Alpen Labs / Strata](https://alpenlabs.io).

Lumora enables confidential deposits, private transfers, and shielded withdrawals using Halo2 zero-knowledge proofs over the Pallas/Vesta curve cycle. It supports cross-chain privacy through domain-separated nullifiers, stealth addresses, and epoch-based nullifier synchronization.

> **Status**: Pre-1.0 (0.1.x). Core circuits have not undergone a formal audit — do not deploy to mainnet. See [SECURITY.md](SECURITY.md).

### Security Hardening

The codebase has undergone extensive hardening across multiple audit rounds:

- **Atomic state transitions** — All contract operations (deposit, transfer, withdraw) pre-check tree capacity before mutating state, preventing partial writes on failure
- **Panic-free tree operations** — All Merkle tree insertions use fallible `try_insert()` with proper error propagation
- **WAL & sync replay safety** — Replay functions validate capacity and balances before mutations; WAL entry size capped at 64 MB to prevent OOM
- **Rate limiting** — Per-IP rate limiter with trusted-proxy-aware X-Forwarded-For extraction (right-to-left walk)
- **Batch limits** — Batch verification capped at 2 MB total proof bytes per request
- **Sync pagination** — `/sync/events` response size bounded to prevent unbounded payloads
- **Proof validation** — Proof size and zero-amount guards in mempool handlers
- **BitVM protocol safety** — Step-kind validation on dispute responses, `saturating_add` for all deadline arithmetic, assertion invariant enforcement

---

## Table of Contents

- [Architecture](#architecture)
- [Crates](#crates)
- [Quick Start](#quick-start)
- [TypeScript SDK](#typescript-sdk)
- [Cryptography](#cryptography)
- [Key Features](#key-features)
- [Documentation](#documentation)
- [Testing & CI](#testing--ci)
- [Project Structure](#project-structure)
- [License](#license)

## Architecture

```
                    ┌──────────────────┐
                    │  @lumora/sdk (TS) │
                    │   HTTP client     │
                    └────────┬─────────┘
                             │
┌────────────────────────────┼────────────────────────────────┐
│                     lumora-cli                              │
│              Interactive REPL binary                        │
└────────────────────────┬───┴────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                     lumora-rpc                              │
│   Axum HTTP server · relay jitter · proof envelope unwrap   │
│   Background: batch_poll_loop · epoch_finalize_loop         │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                     lumora-sdk                              │
│           Unified orchestrator (Lumora)                     │
│        deposit() → send() → withdraw()                     │
└──────┬─────────────────────────────────┬────────────────────┘
       │                                 │
┌──────▼──────────┐            ┌─────────▼────────┐
│   lumora-node   │            │  lumora-client   │
│  Prover daemon  │            │  Wallet / keys   │
│  Note relay     │            │  Note tracking   │
│  Batch accum.   │            │  Coin selection  │
└──────┬──────────┘            └──────────────────┘
       │
┌──────▼──────────────────────────────────────────────────────┐
│                   lumora-contracts                          │
│   PrivacyPool: deposit / transfer / withdraw               │
│   EpochManager · WAL · Snapshots · Compliance              │
└──────┬──────────────────┬───────────────────────────────────┘
       │                  │
┌──────▼────────┐  ┌──────▼────────┐
│ lumora-prover │  │lumora-verifier│
│ prove_transfer│  │verify_transfer│
│ prove_withdraw│  │verify_withdraw│
│ async pipeline│  │ batch verify  │
└──────┬────────┘  └───────────────┘
       │
┌──────▼──────────────────────────────────────────────────────┐
│                   lumora-circuits                           │
│   TransferCircuit (2-in-2-out, k=13)                       │
│   WithdrawCircuit (2-in-2-out + exit_value)                │
│   WealthProof (k=15) · Aggregation · Recursive             │
└──────┬──────────────────┬───────────────────────────────────┘
       │                  │
┌──────▼──────┐   ┌───────▼──────┐   ┌──────────────────┐
│ lumora-note │   │ lumora-tree  │   │lumora-primitives │
│ Note, keys  │   │ Merkle tree  │   │ Poseidon hash    │
│ Encryption  │   │ depth=32     │   │ Pedersen commit  │
│ Stealth addr│   │              │   │ Proof envelopes  │
└─────────────┘   └──────────────┘   └──────────────────┘
```

## Crates

| Crate               | Description                                                                                                                        |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `lumora-primitives` | Pallas/Vesta type aliases, Poseidon hash (P128Pow5T3), Pedersen commitment, fixed-size proof envelopes                             |
| `lumora-note`       | Note, SpendingKey, ViewingKey, NoteCommitment, Nullifier (V1+V2 domain-separated), stealth addresses, ChaCha20-Poly1305 encryption |
| `lumora-tree`       | Append-only incremental Merkle tree (depth 32, Poseidon)                                                                           |
| `lumora-circuits`   | Halo2 circuits: TransferCircuit, WithdrawCircuit, aggregation, recursive, variable I/O, wealth proof                               |
| `lumora-prover`     | ZK proof generation (setup, prove, async prove, parallel pipelines)                                                                |
| `lumora-verifier`   | Proof verification (verify_transfer, verify_withdraw, batch verify)                                                                |
| `lumora-contracts`  | PrivacyPool state machine, rollup bridge, epoch nullifier manager, compliance, governance                                          |
| `lumora-node`       | Prover daemon (LumoraNode) + encrypted note store + batch accumulator                                                              |
| `lumora-client`     | Client wallet: key management, note tracking, coin selection                                                                       |
| `lumora-sdk`        | High-level `Lumora` orchestrator + serialization helpers                                                                           |
| `lumora-rpc`        | Axum HTTP server, relay jitter middleware, proof envelope unwrap, epoch-roots endpoint                                             |
| `lumora-cli`        | Interactive CLI (`lumora run`)                                                                                                     |
| `lumora-bitvm`      | BitVM2 bridge: operator, challenger, optimistic verification, 14 adapters (13 Bitcoin L2/sidechain + EMVCo QR [ALPHA])              |

## Quick Start

```bash
# Build
cargo build

# Run all tests
cargo test --lib -- --test-threads=1

# Run the e2e example (deposit → transfer → withdraw)
cargo run -p lumora-sdk --example e2e

# Run the CLI
cargo run -p lumora-cli -- run
```

### SDK Usage

```rust
use lumora_sdk::Lumora;
use pasta_curves::pallas;

let mut lumora = Lumora::init(); // generates proving keys (~seconds)

// Deposit 100 into the pool
lumora.deposit(100).unwrap();

// Private transfer: send 70 to a recipient
let recipient_owner = pallas::Base::from(0xBEEF_u64);
let recipient_pk: pallas::Point = /* recipient's public key for encryption */;
lumora.send(recipient_owner, recipient_pk, 70).unwrap();

// Withdraw 30 back to an external address
let addr = [0u8; 32];
lumora.withdraw(30, addr).unwrap();

// Check transaction history
for tx in lumora.wallet.history() {
    println!("{tx:?}");
}
```

### CLI Session

```
$ cargo run -p lumora-cli -- run
Initializing Lumora node (generating proving keys)...
Ready. Wallet owner: 2f3a...

lumora> deposit 100
Deposited 100. Leaf index: 0. Root: a1b2...

lumora> balance
Wallet balance : 100
Pool balance   : 100

lumora> send <recipient_hex> 70
Sent 70. Proof size: 1888 bytes. Nullifiers spent: 2

lumora> withdraw 30
Withdrew 30. Change leaf indices: [4, 5]. Root: c3d4...

lumora> history
[0] Deposit 100 (asset 0) → leaf 0
[1] Send 70 (asset 0) → abcd...
[2] Withdraw 30 (asset 0)

lumora> save-wallet wallet.json
Wallet saved to wallet.json

lumora> quit
```

## Cryptography

| Component          | Scheme                                                    |
| ------------------ | --------------------------------------------------------- |
| Proving system     | Halo2 (zcash fork) — no trusted setup                     |
| Curve cycle        | Pallas / Vesta (pasta curves)                             |
| Hash function      | Poseidon (P128Pow5T3, width=3, rate=2)                    |
| Commitment         | Poseidon-based (in-circuit) + Pedersen (out-of-circuit)   |
| Nullifier (V1)     | Poseidon(spending_key, commitment)                        |
| Nullifier (V2)     | Poseidon(Poseidon(sk, cm), Poseidon(chain_id, app_id))    |
| Stealth addresses  | ECDH on Pallas + Poseidon one-time owner derivation       |
| Merkle tree        | Poseidon-based, depth 32, append-only                     |
| Note encryption    | ECDH on Pallas + HKDF-SHA256 KDF + ChaCha20-Poly1305 AEAD |
| Wallet encryption  | AES-256-GCM with Argon2 KDF                               |
| Key derivation     | BIP39 mnemonic → PBKDF2 seed → Pallas scalar              |
| Nullifier registry | Constant-time equality (subtle crate)                     |
| Circuit size       | k=13 (transfer/withdraw), k=15 (wealth proof)             |

## TypeScript SDK

The `@lumora/sdk` package provides a typed HTTP client for all RPC endpoints:

```typescript
import { LumoraClient } from "@lumora/sdk";

const client = new LumoraClient("http://127.0.0.1:3030", "my-api-key");

// Check pool status
const status = await client.status();
console.log(`Pool balance: ${status.pool_balance}`);

// Deposit
const receipt = await client.deposit({ commitment: "0xaabb...", amount: 1000 });

// Private transfer with domain-separated nullifiers
await client.transfer({
  proof_bytes: "...",
  merkle_root: "...",
  nullifiers: ["...", "..."],
  output_commitments: ["...", "..."],
  domain_chain_id: 1,
  domain_app_id: 42,
});

// Stealth address scanning (client-side trial decryption)
const notes = await client.stealthScan({ from_leaf_index: 0, limit: 500 });

// Cross-chain epoch roots
const epochs = await client.epochRoots();
```

See [docs/typescript-sdk.md](docs/typescript-sdk.md) for the complete API reference.

## Documentation

### Guides

- [docs/getting-started.md](docs/getting-started.md) — Installation, first deposit, SDK and CLI quickstart
- [docs/api-guide.md](docs/api-guide.md) — Complete RPC API reference (17 endpoints)
- [docs/typescript-sdk.md](docs/typescript-sdk.md) — TypeScript SDK setup, API reference, and examples
- [docs/architecture.md](docs/architecture.md) — System architecture, data flow, and component responsibilities
- [docs/cross-chain-privacy.md](docs/cross-chain-privacy.md) — Domain-separated nullifiers, epochs, and cross-chain sync
- [docs/stealth-addresses.md](docs/stealth-addresses.md) — Stealth address protocol, scanning, and privacy considerations
- [docs/troubleshooting.md](docs/troubleshooting.md) — Common issues, debugging tips, and FAQ

### Specifications

- [PROTOCOL.md](PROTOCOL.md) — Formal protocol specification (primitives, operations, circuit constraints)
- [docs/circuit-constraints.md](docs/circuit-constraints.md) — Circuit constraint reference (transfer, withdraw, range checks)
- [docs/cryptography.md](docs/cryptography.md) — Cryptographic primitives, key hierarchy, and security parameters
- [docs/light-client-design.md](docs/light-client-design.md) — Light client architecture and trust models
- [docs/state-persistence.md](docs/state-persistence.md) — WAL, snapshots, and crash recovery

### Operations & Security

- [DEPLOYMENT.md](DEPLOYMENT.md) — Production deployment guide (Docker, Helm, configuration)
- [docs/upgrade-runbook.md](docs/upgrade-runbook.md) — Upgrade procedures, state migration, nullifier V1→V2 transition
- [BENCHMARKS.md](BENCHMARKS.md) — Performance benchmarks (proof generation, verification, memory)
- [THREAT_MODEL.md](THREAT_MODEL.md) — Threat model (trust boundaries, attack surface, mitigations)
- [SECURITY.md](SECURITY.md) — Security policy and vulnerability disclosure process

### Project

- [CHANGELOG.md](CHANGELOG.md) — Complete changelog (Phases 1–36)
- [CONTRIBUTING.md](CONTRIBUTING.md) — Contributing guidelines and development workflow
- [VERSIONING.md](VERSIONING.md) — Semantic versioning policy
- [docs/adr/](docs/adr/) — Architecture Decision Records (7 decisions)

## Key Features

- **Fee-aware circuits** — Transfer and withdraw circuits enforce `sum(inputs) == sum(outputs) + fee [+ exit_value]`
- **Dynamic fee model** — Congestion-aware fee estimation (`DynamicFeeEstimator`) with configurable base rates, per-byte costs, and priority tiers
- **Async proof generation** — `tokio::spawn_blocking` wrappers for non-blocking proof gen in server contexts
- **Rollup integration** — `StrataBridge` with pluggable JSON-RPC 2.0 transport, deposit finality tracking, atomic deposit/withdrawal coordinator
- **Proof aggregation** — Aggregation bundles and recursive proving with Halo2 IPA verification
- **On-chain IPA verifier** — Real `IpaTransferVerifier` performing full cryptographic proof verification
- **Variable I/O** — Circuit scaffolding for up to 8-in-8-out transactions (beyond fixed 2-in-2-out)
- **ZK wealth proofs** — Prove total balance exceeds a threshold without revealing exact amounts (k=15 circuit)
- **Compliance hooks** — `ComplianceOracle` trait, viewing key disclosure, selective transparency
- **WAL + snapshots** — Write-ahead logging with periodic snapshots for crash recovery; WAL files written with `0o600` permissions on Unix
- **Per-IP rate limiting** — `IpRateLimiter` enforces 60 req/min per IP with `X-Forwarded-For` awareness
- **Wallet management** — Multi-wallet manager with BIP-39 mnemonic creation/recovery, encrypted backup/restore (AES-256-GCM + Argon2)
- **TypeScript SDK** — Full HTTP client (`@lumora/sdk`) with 17 endpoint methods, stealth scanning, epoch root queries, and domain field support
- **Domain-separated nullifiers** — V2 nullifiers include `(chain_id, app_id)` for cross-chain isolation; backward-compatible V1 path preserved
- **Stealth addresses** — ECDH-based one-time stealth addresses; sender creates via `stealth_send()`, recipient detects via `stealth_receive()`
- **Metadata resistance** — Fixed-size 2048-byte proof envelopes, transaction batch accumulator with dummy padding, relay jitter middleware
- **Epoch nullifier partitioning** — `EpochManager` partitions nullifiers into time-bounded epochs with Merkle root finalization
- **Cross-chain nullifier sync** — `RollupBridge` publishes per-epoch nullifier roots and fetches roots from remote chains
- **BitVM2 bridge** — Optimistic Bitcoin L1 verification via `BitvmBridge`; operator/challenger protocol with bonded assertions, challenge-response, and timeout-based finality; 14 adapters (13 Bitcoin L2/sidechain + EMVCo QR payment rail [ALPHA])
- **Hardened state machine** — All contract operations guard mutations with capacity/balance pre-checks; panic-free tree operations; WAL entry caps; replay atomicity

## Testing & CI

**350+ Rust lib tests · 24 integration/E2E tests · 30 TypeScript tests · 24 Python tests · 11 fuzz targets**

```bash
# Unit + integration tests (350+ lib tests across 13 crates)
cargo test --lib -- --test-threads=1

# RPC endpoint tests (36 lib + 12 E2E)
cargo test -p lumora-rpc

# Cross-crate integration tests (9 tests)
cargo test -p lumora-contracts --test cross_crate

# TypeScript SDK tests (30 tests)
cd sdks/typescript && npm test

# Python SDK tests (24 tests)
cd sdks/python && python -m pytest

# Property-based tests (proptest)
cargo test -p lumora-contracts proptest
cargo test -p lumora-primitives -- proptests

# Fuzz testing (requires cargo-fuzz, 11 targets)
cargo fuzz run envelope -- -max_total_time=60
cargo fuzz run field_parse -- -max_total_time=60
cargo fuzz run transfer_json -- -max_total_time=60
cargo fuzz run wal_entry -- -max_total_time=60
cargo fuzz run bitvm_protocol -- -max_total_time=60
cargo fuzz run bitvm_merkle -- -max_total_time=60
cargo fuzz run bitvm_trace_step -- -max_total_time=60
cargo fuzz run bitvm_adapter_parse -- -max_total_time=60
cargo fuzz run poseidon_merkle -- -max_total_time=60
cargo fuzz run pedersen_commit -- -max_total_time=60
cargo fuzz run emv_deposit_parse -- -max_total_time=60

# Nullifier migration (V1 → V2)
cargo run -p lumora-cli -- migrate-nullifiers --wallet wallet.json --chain-id 1 --app-id 42 --dry-run

# Benchmarks (criterion)
cargo bench -p lumora-contracts
```

GitHub Actions CI runs: lint/fmt check, full test suite, `cargo deny`, `cargo audit`, TypeScript SDK build+test, Python SDK tests, slow proof tests (30 min timeout), benchmark regression comparison, and benchmark validation. Dependabot monitors Cargo, npm, pip, and GitHub Actions dependencies weekly.

## Project Structure

```
lumora/
├── Cargo.toml                # Workspace root (13 crates)
├── crates/
│   ├── lumora-primitives/     # Field types, Poseidon, Pedersen, proof envelopes
│   ├── lumora-note/           # Note model, keys, ECIES, stealth addresses
│   ├── lumora-tree/           # Incremental Merkle tree (depth 32)
│   ├── lumora-circuits/       # Halo2 ZK circuits (transfer, withdraw, wealth)
│   ├── lumora-prover/         # Proof generation + async pipeline
│   ├── lumora-verifier/       # Proof verification + batch verify
│   ├── lumora-contracts/      # Privacy pool state machine + epoch manager
│   ├── lumora-bitvm/          # BitVM2 bridge: operator, challenger, 14 adapters
│   ├── lumora-node/           # Prover daemon, note store, batch accumulator
│   ├── lumora-client/         # Client wallet + key management
│   ├── lumora-sdk/            # High-level orchestrator
│   ├── lumora-rpc/            # Axum HTTP server + background tasks
│   └── lumora-cli/            # Interactive CLI binary
├── sdks/
│   ├── typescript/            # @lumora/sdk — TypeScript HTTP client
│   └── python/                # lumora-sdk — Python client (24 tests)
├── docs/                      # Guides, specs, and ADRs
├── deploy/helm/               # Kubernetes Helm chart
├── benches/                   # Criterion benchmarks
├── tests/                     # Cross-crate integration tests
├── fuzz/                      # cargo-fuzz targets (11 fuzz harnesses)
├── .github/
│   ├── workflows/ci.yml       # GitHub Actions CI
│   ├── workflows/release.yml  # Tag-triggered release workflow
│   └── dependabot.yml         # Automated dependency updates
├── Dockerfile                 # Container build
├── docker-compose.yml         # Local dev stack
└── deny.toml                  # Supply chain audit config
```

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE). See the license files for details.
