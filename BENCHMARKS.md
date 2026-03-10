# Lumora Performance Benchmarks

Measured on Apple M-series (arm64), `--release` profile, single-threaded unless noted.

> **Note**: These are approximate measurements for development reference. Production
> performance depends on hardware, OS, and concurrent workload. Always benchmark on
> your target deployment environment.

## Circuit Parameters

| Parameter               | Value                                     |
| ----------------------- | ----------------------------------------- |
| Curve                   | Pallas / Vesta                            |
| Circuit size (K)        | 13 (2^13 = 8192 rows)                     |
| Merkle tree depth       | 32                                        |
| Range check             | 64-bit successive halving (65 rows/value) |
| Transfer inputs/outputs | 2-in / 2-out                              |
| Nullifier version       | V2 (domain-separated)                     |
| Proof envelope size     | 2048 bytes (fixed, padded)                |

## Key Generation (one-time)

| Operation            | Approx. Time | Notes                                                    |
| -------------------- | ------------ | -------------------------------------------------------- |
| SRS generation       | ~2-4 s       | `Params::new(K=13)` — can be cached to disk              |
| Transfer keygen      | ~1-2 s       | `keygen_vk` + `keygen_pk`                                |
| Withdraw keygen      | ~1-3 s       | Slightly larger circuit (exit_value + extra range check) |
| **Total cold start** | **~5-9 s**   | First run; subsequent runs load cached SRS (~0.1 s)      |

## Proof Generation

| Operation        | Approx. Time | Proof Size | Envelope Size |
| ---------------- | ------------ | ---------- | ------------- |
| Transfer proof   | ~3-6 s       | ~5-7 KB    | 2048 B        |
| Withdrawal proof | ~3-7 s       | ~5-8 KB    | 2048 B        |

Proof envelopes pad all proofs to a fixed 2048-byte size (random padding) to prevent
proof-size side channels.

## Proof Verification

| Operation               | Approx. Time    | Notes                         |
| ----------------------- | --------------- | ----------------------------- |
| Single transfer verify  | ~10-20 ms       |                               |
| Single withdraw verify  | ~10-25 ms       |                               |
| Batch verify (N proofs) | ~(10 + 5\*N) ms | Amortised via `BatchVerifier` |
| Envelope unwrap         | < 0.01 ms       | Version check + length parse  |

## Batch Accumulator & Epoch Manager

| Operation                   | Approx. Time | Frequency  | Notes                                  |
| --------------------------- | ------------ | ---------- | -------------------------------------- |
| Batch poll (collect + hash) | < 1 ms       | Every 5 s  | Poseidon hash of new commitments       |
| Epoch finalization          | < 5 ms       | Every 60 s | Poseidon hash of batch roots           |
| Epoch root serialization    | < 0.1 ms     | On demand  | JSON response for /v1/epoch-roots      |
| Stealth scan (1K notes)     | < 10 ms      | On demand  | Linear scan, no decryption server-side |

### Throughput Estimates

| Metric                    | Value         | Notes                                   |
| ------------------------- | ------------- | --------------------------------------- |
| Max commitments per batch | ~50-200       | Depends on transaction rate             |
| Max batches per epoch     | ~12           | 60 s epoch / 5 s batch interval         |
| Max epochs per hour       | 60            | One epoch per minute                    |
| Stealth scan throughput   | ~100K notes/s | CPU-bound Poseidon hash + memory access |
| Cross-chain sync payload  | < 1 KB/epoch  | epoch_id + root + height + timestamp    |

## Wallet & State Operations

| Operation                             | Approx. Time | Notes                     |
| ------------------------------------- | ------------ | ------------------------- |
| Wallet save (JSON)                    | < 1 ms       |                           |
| Wallet load (JSON)                    | < 1 ms       |                           |
| Wallet encrypt (Argon2 + AES-256-GCM) | ~100-300 ms  | Dominated by Argon2 KDF   |
| Pool state save/load                  | < 5 ms       | Depends on tree size      |
| Note store save/load                  | < 1 ms       |                           |
| WAL append + fsync                    | < 1 ms       | Single event              |
| Snapshot write (1M leaves)            | ~50-100 ms   | Binary + HMAC             |
| Snapshot load (1M leaves)             | ~30-60 ms    | HMAC verify + deserialize |

## Commitment Computation

| Operation                  | Approx. Time | Notes                       |
| -------------------------- | ------------ | --------------------------- |
| Poseidon hash (1 call)     | < 0.01 ms    |                             |
| Note commitment            | < 0.05 ms    | 2× Poseidon (inner + outer) |
| Nullifier V1 derivation    | < 0.01 ms    | H(sk ‖ cm)                  |
| Nullifier V2 derivation    | < 0.02 ms    | H(domain ‖ sk ‖ cm)         |
| Domain tag computation     | < 0.01 ms    | SHA-256(prefix ‖ chain_id)  |
| Merkle witness (depth 32)  | < 0.1 ms     |                             |
| Stealth address derivation | < 0.1 ms     | ECDH + Poseidon             |

## RPC Endpoint Latency

Measured locally (loopback) with a warm server (SRS cached):

| Endpoint           | Method | Approx. Latency | Notes                     |
| ------------------ | ------ | --------------- | ------------------------- |
| `/health`          | GET    | < 1 ms          | No auth required          |
| `/v1/status`       | GET    | < 1 ms          |                           |
| `/v1/fees`         | GET    | < 1 ms          |                           |
| `/v1/deposit`      | POST   | ~3-6 s          | Dominated by proof gen    |
| `/v1/transfer`     | POST   | ~3-6 s          | Dominated by proof gen    |
| `/v1/withdraw`     | POST   | ~3-7 s          | Dominated by proof gen    |
| `/v1/nullifier`    | POST   | < 1 ms          | Set lookup                |
| `/v1/merkle-proof` | POST   | < 1 ms          | Tree traversal            |
| `/v1/epoch-roots`  | GET    | < 1 ms          | Returns finalized epochs  |
| `/v1/stealth-scan` | POST   | < 10 ms         | Linear scan of note store |
| `/v1/batch-verify` | POST   | ~(10 + 5\*N) ms | N proofs                  |
| `/v1/history`      | GET    | < 1 ms          | Event log query           |
| `/v1/metrics`      | GET    | < 1 ms          | Prometheus counters       |

## Memory Usage

| Component                 | Approx. Memory  |
| ------------------------- | --------------- |
| SRS params (K=13)         | ~130 MB         |
| Proving key (transfer)    | ~50-100 MB      |
| Proving key (withdraw)    | ~50-100 MB      |
| Merkle tree (1M leaves)   | ~32 MB          |
| Epoch history (1K epochs) | < 1 MB          |
| Batch accumulator state   | < 1 MB          |
| RPC server overhead       | ~10-20 MB       |
| **Total node footprint**  | **~300-400 MB** |

## Disk Usage

| File                         | Approx. Size |
| ---------------------------- | ------------ |
| `srs.bin`                    | ~130 MB      |
| `pool_state.json` (1K notes) | ~200 KB      |
| `pool_state.bin` (1K notes)  | ~150 KB      |
| `note_store.json` (1K notes) | ~300 KB      |
| `wallet.json`                | < 10 KB      |
| `wal.log` (1K events)        | ~100 KB      |
| `snapshot_NNNNNN.bin`        | ~200 KB      |

## How to Benchmark

```bash
# Build in release mode
cargo build --release

# Run all tests (includes proof generation)
cargo test --release -- --nocapture 2>&1 | grep -E "test .* ok"

# Time a specific heavy test
time cargo test --release -p lumora-prover -- test_transfer_proof_roundtrip --nocapture

# Benchmark batch verification
time cargo test --release -p lumora-verifier -- test_batch_verify --nocapture

# RPC endpoint latency (requires a running server)
LUMORA_API_KEY=test cargo run --release -p lumora-rpc &
curl -w "%{time_total}s\n" -s -o /dev/null http://127.0.0.1:3030/health

# Profile with flamegraph (requires cargo-flamegraph)
cargo flamegraph --release --test integration -- test_name

# TypeScript SDK tests
cd sdks/typescript && npm test
```

## Optimization Opportunities

1. **SRS caching** — `LumoraNode::init_cached()` saves ~4 s on restart.
2. **Batch verification** — `batch_verify_transfers()` amortises MSM cost.
3. **Parallel proving** — rayon-based proving (future: #35).
4. **Circuit packing** — current K=13 utilises ~50-60% of rows; room for additional gadgets without increasing K.
5. **Epoch root caching** — Finalized epoch roots are immutable and can be served from memory.
6. **Stealth scan pagination** — Clients can scan incrementally using `from_leaf_index` to avoid re-scanning.
7. **Proof envelope pre-allocation** — Fixed 2048-byte buffers can be pooled to reduce allocation overhead.
8. **Background task tuning** — Batch interval (5 s) and epoch interval (60 s) are configurable for latency vs. throughput tradeoff.

## Related Documents

- [Architecture](docs/architecture.md) — System design and data flow
- [Circuit Constraints](docs/circuit-constraints.md) — ZK circuit constraint tables
- [Cryptography](docs/cryptography.md) — Cryptographic primitives
- [Deployment](DEPLOYMENT.md) — Production deployment guide
