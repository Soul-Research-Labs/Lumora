# Lumora Deployment Guide

This document covers building, configuring, and running Lumora in production-like
environments.

## Prerequisites

| Requirement | Minimum                            |
| ----------- | ---------------------------------- |
| Rust        | 1.75+ (edition 2021)               |
| OS          | Linux x86-64 / macOS arm64         |
| RAM         | ≥ 4 GB (SRS generation + proving)  |
| Disk        | ≥ 500 MB (build artefacts + state) |

## Building

### Release build

```bash
cargo build --release
```

This produces two binaries in `target/release/`:

| Binary       | Purpose                                    |
| ------------ | ------------------------------------------ |
| `lumora-cli` | Interactive command-line wallet and prover |
| `lumora-rpc` | HTTP JSON-RPC server                       |

### Verify

```bash
cargo test --workspace --lib
```

## Running the RPC Server

The RPC server exposes a JSON API for deposits, transfers, withdrawals, and state
queries.

```bash
# Default: listens on 127.0.0.1:3030
./target/release/lumora-rpc

# Custom address
LUMORA_RPC_ADDR=0.0.0.0:8080 ./target/release/lumora-rpc
```

### Environment variables

| Variable               | Default          | Description                                      |
| ---------------------- | ---------------- | ------------------------------------------------ |
| `LUMORA_RPC_ADDR`      | `127.0.0.1:3030` | Listen address (`host:port`)                     |
| `LUMORA_API_KEY`       | _(none)_         | API key for `X-API-Key` authentication           |
| `LUMORA_DATA_DIR`      | `./lumora_data`  | Data directory (SRS cache, state, WAL)           |
| `LUMORA_JITTER_MIN_MS` | `50`             | Relay jitter minimum delay (ms)                  |
| `LUMORA_JITTER_MAX_MS` | `500`            | Relay jitter maximum delay (ms)                  |
| `RUST_LOG`             | _(none)_         | Logging filter (e.g. `info`, `lumora_rpc=debug`) |

> **Note:** `MAX_BODY_SIZE` (2 MB) and `MAX_CONCURRENT_REQUESTS` (128) are
> compile-time constants in `server.rs`, not configurable via environment
> variables. To change them, modify the constants and rebuild.

### Startup

On first launch the server generates the structured reference string (SRS) and
proving keys for the Halo2 circuits (k = 13). This takes a few seconds and is
cached in memory for the lifetime of the process.

### API Endpoints

All endpoints are available at the root (`/deposit`) and under the versioned
prefix (`/v1/deposit`). Prefer the `/v1/` prefix for forward-compatibility.

| Method | Path               | Description                                   |
| ------ | ------------------ | --------------------------------------------- |
| GET    | `/health`          | Liveness probe (no auth required)             |
| GET    | `/v1/status`       | Pool balance, commitment count, Merkle root   |
| GET    | `/v1/fees`         | Transfer, withdraw, and deposit fee estimates |
| POST   | `/v1/deposit`      | Create a shielded deposit                     |
| POST   | `/v1/transfer`     | Private 2-in-2-out transfer with ZK proof     |
| POST   | `/v1/withdraw`     | Unshield funds with ZK proof + exit value     |
| POST   | `/v1/nullifier`    | Check whether a nullifier has been spent      |
| POST   | `/v1/relay-note`   | Store an encrypted note for a recipient       |
| POST   | `/v1/notes`        | Retrieve encrypted notes by recipient tag     |
| POST   | `/v1/history`      | Paginated event history                       |
| GET    | `/v1/sync/status`  | Node sync height, root, nullifier count       |
| POST   | `/v1/sync/events`  | Fetch state deltas from a given height        |
| POST   | `/v1/batch-verify` | Batch verify multiple transfer proofs         |
| GET    | `/v1/epoch-roots`  | Finalized nullifier-epoch Merkle roots        |
| POST   | `/v1/stealth-scan` | Download notes for stealth address detection  |
| GET    | `/metrics`         | Prometheus metrics (no auth required)         |

Request/response schemas: `crates/lumora-rpc/src/types.rs`.
Full API reference: [docs/api-guide.md](docs/api-guide.md).

### Background Tasks

The RPC server automatically starts two background tasks:

| Task                  | Interval   | Purpose                                                                                                                                             |
| --------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `batch_poll_loop`     | 5 seconds  | Flushes the `BatchAccumulator` — releases buffered transactions when min batch size is met, pads with dummy transactions when max wait time expires |
| `epoch_finalize_loop` | 60 seconds | Finalizes the current nullifier epoch via `EpochManager`, computes the epoch Merkle root, and advances to the next epoch                            |

Both tasks share the `AppState` (`Arc<RwLock<LumoraNode>>`) with the HTTP
router. Task handles are aborted on graceful server shutdown.

## Running the CLI

```bash
./target/release/lumora-cli run
```

The CLI initialises a local node with an in-memory wallet and provides an
interactive REPL for deposits, transfers, withdrawals, balance checks, and wallet
management.

## State Persistence

### Wallet

```rust
// Save encrypted wallet (AES-256-GCM + Argon2 key derivation)
wallet.save_encrypted(Path::new("wallet.enc"), "passphrase")?;

// Load
let wallet = Wallet::load_encrypted(Path::new("wallet.enc"), "passphrase")?;
```

Key material is zeroized from memory after encryption/decryption.

### Merkle Tree

The privacy pool state (Merkle tree, nullifier set) lives in-process memory.
For persistence across restarts, the node replays deposit/transfer/withdraw
events from the event log. See `PrivacyPoolState::save()` / `load()` in
`crates/lumora-contracts/src/state.rs`.

### Peer Registry

The `PeerRegistry` supports JSON persistence:

```rust
registry.save(Path::new("peers.json"))?;
let registry = PeerRegistry::load(Path::new("peers.json"))?;
```

## Standalone Mode

By default Lumora runs standalone with a `LocalBridge` (no-op rollup
integration). All operations execute locally without an external L1/L2
connection:

```
lumora-rpc  ──  LumoraNode (prover + verifier + pool)
                    │
                LocalBridge (no-op)
```

This is suitable for development, testing, and single-operator deployments.

## Rollup Integration

To connect Lumora to an external rollup, implement the `RollupBridge` trait
(`crates/lumora-contracts/src/bridge.rs`):

```rust
pub trait RollupBridge {
    fn poll_deposits(&mut self) -> Result<Vec<InboundDeposit>, BridgeError>;
    fn execute_withdrawal(&mut self, w: &OutboundWithdrawal) -> Result<(), BridgeError>;
    fn commit_state_root(&mut self, root: [u8; 32]) -> Result<(), BridgeError>;
}
```

This allows polling L1 deposit events, submitting withdrawal proofs, and
committing Merkle roots to the host chain.

## Multi-Node Sync

Two or more Lumora nodes can synchronize state via the sync protocol:

1. **Query remote status**: `GET /sync/status` returns height, root, nullifier
   count, and pool balance.
2. **Fetch deltas**: `POST /sync/events` with `{ "from_height": N }` returns the
   list of pool events since height N.
3. **Apply locally**: `apply_delta(node, delta)` replays events to bring a
   follower node up to date.

The sync protocol (`crates/lumora-node/src/sync.rs`) is designed for trusted
leader-follower replication. Full re-verification of transferred proofs is
planned for a future release.

## Mempool

The transaction mempool (`crates/lumora-node/src/mempool.rs`) buffers pending
transactions before they are included in state updates:

- Bounded FIFO queue (default max: 1024 transactions)
- Submit via `/submit-deposit`, `/submit-transfer`, `/submit-withdraw`
- Query via `GET /mempool/status`

## Security Considerations

- **Bind address**: Default is `127.0.0.1` (localhost only). Use `0.0.0.0` only
  behind a reverse proxy or firewall.
- **TLS**: The RPC server does not provide TLS. Use a reverse proxy (nginx,
  Caddy) for HTTPS in production.
- **Authentication**: Set `LUMORA_API_KEY` to enable `X-API-Key` header
  authentication. For production, add mutual TLS or OAuth2 at the proxy layer.
- **Key material**: Spending keys are redacted in debug output. Wallet
  encryption uses Argon2id + AES-256-GCM with key zeroization.
- **Blinding factors**: All randomness uses full-width Pallas scalars via
  `OsRng`.
- **Proof envelopes**: All proofs are padded to 2048 bytes to prevent
  operation type inference from proof size.
- **Relay jitter**: POST responses are delayed by 50–500ms (configurable) to
  decorrelate sender and relay timing.
- **Rate limiting**: Per-IP rate limiting (60 req/min) is enforced in the
  middleware layer. The client IP is extracted from the `X-Forwarded-For`
  header (set this at the reverse proxy).

### TLS Termination

The Lumora RPC server does not handle TLS directly. Use a reverse proxy to
terminate TLS before forwarding to the server:

**Nginx example** (`/etc/nginx/sites-available/lumora`):

```nginx
server {
    listen 443 ssl;
    server_name lumora.example.com;

    ssl_certificate     /etc/letsencrypt/live/lumora.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/lumora.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:3030;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
    }
}
```

**Caddy example** (`Caddyfile`):

```
lumora.example.com {
    reverse_proxy 127.0.0.1:3030
}
```

Caddy automatically provisions and renews Let's Encrypt certificates.

## Monitoring and Observability

### Prometheus Metrics

The `/metrics` endpoint exposes:

- `http_requests_total{method, path, status}` — request counter
- `http_request_duration_seconds{method, path}` — latency histogram
- `http_requests_rejected_total{reason}` — rejections (auth, overload)

### Logging

Structured logging via `tracing`. Configure with `RUST_LOG`:

```bash
# Info level for all crates
RUST_LOG=info ./target/release/lumora-rpc

# Debug for RPC, info for everything else
RUST_LOG=info,lumora_rpc=debug ./target/release/lumora-rpc

# Trace level for request/response details
RUST_LOG=lumora_rpc=trace ./target/release/lumora-rpc
```

### Health Checks

- **Liveness**: `GET /health` returns `200 OK` with body `ok`.
- **Readiness**: `GET /v1/status` returns pool state (returns 500 if node is
  not initialized).

## Docker

### Build

```bash
docker build -t lumora .
```

### Run

```bash
docker run -p 3030:3030 \
  -e LUMORA_API_KEY=my-secret-key \
  -e LUMORA_RPC_ADDR=0.0.0.0:3030 \
  -e RUST_LOG=info \
  -v lumora-data:/data \
  -e LUMORA_DATA_DIR=/data \
  lumora
```

### Docker Compose

```bash
docker-compose up -d
```

The `docker-compose.yml` in the repository root starts the RPC server with
persistent volumes for state data. Configure via environment variables or
a `.env` file.

**Docker secrets (recommended for production):**

```bash
mkdir -p secrets
echo "your-strong-api-key" > secrets/api_key.txt
chmod 600 secrets/api_key.txt
docker-compose up -d
```

The compose file mounts the secret at `/run/secrets/lumora_api_key`. In
a Docker Swarm deployment, use `docker secret create` instead of a file.

## Kubernetes (Helm)

```bash
cd deploy/helm
helm install lumora lumora/ \
  --set apiKey=my-secret-key \
  --set replicas=1 \
  --set resources.memory=512Mi \
  --set persistence.size=1Gi
```

See `deploy/helm/lumora/values.yaml` for all configurable parameters.

## Resource Requirements

| Operation                     | Time (approx.) | Memory  |
| ----------------------------- | -------------- | ------- |
| SRS generation (k=13)         | 1-3 s          | ~200 MB |
| Deposit proof                 | 0.5-1 s        | ~100 MB |
| Transfer proof                | 1-3 s          | ~200 MB |
| Withdraw proof                | 1-3 s          | ~200 MB |
| Batch verification (8 proofs) | < 0.5 s        | ~50 MB  |

Benchmarks: see [BENCHMARKS.md](BENCHMARKS.md).
