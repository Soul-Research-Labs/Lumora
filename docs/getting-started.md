# Getting Started

## Prerequisites

- **Rust 1.75+** (stable toolchain)
- **Cargo** (comes with Rust)
- **Node.js 18+** and **npm** (for TypeScript SDK, optional)
- ~500 MB free disk space (SRS parameters + build artifacts)
- ~4 GB RAM (ZK proof generation is memory-intensive)

## Build

```bash
# Clone the repository
git clone https://github.com/lumora/lumora.git
cd lumora

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace --lib -- --test-threads=1
```

## Quick End-to-End Example

### Start the RPC server

```bash
# Generates proving keys on first run (~5–9 seconds)
LUMORA_API_KEY=my-secret-key cargo run -p lumora-rpc
```

### Interact via curl

```bash
# Check health (no auth required)
curl http://127.0.0.1:3030/health

# Check pool status
curl -H "X-API-Key: my-secret-key" http://127.0.0.1:3030/v1/status

# Get fee estimates
curl -H "X-API-Key: my-secret-key" http://127.0.0.1:3030/v1/fees

# Deposit funds
curl -s -X POST http://127.0.0.1:3030/v1/deposit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{"commitment":"aabb...64hex...", "amount":1000}'

# Check if a nullifier has been spent
curl -s -X POST http://127.0.0.1:3030/v1/nullifier \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{"nullifier":"ccdd...64hex..."}'

# Fetch finalized epoch roots (cross-chain sync)
curl -H "X-API-Key: my-secret-key" http://127.0.0.1:3030/v1/epoch-roots

# Stealth scan (download notes for local trial decryption)
curl -s -X POST http://127.0.0.1:3030/v1/stealth-scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{"from_leaf_index": 0, "limit": 100}'
```

## Using the Rust SDK

```rust
use lumora_sdk::Lumora;

fn main() {
    // Initialize (generates SRS + proving keys)
    let mut lumora = Lumora::init();

    // Deposit 1000 into the privacy pool
    let receipt = lumora.deposit(1000).unwrap();
    println!("Deposited at leaf index: {}", receipt.leaf_index);

    // Private transfer: send 500 to a recipient
    let recipient = /* recipient's owner field */;
    let recipient_pk = /* recipient's public key for encryption */;
    lumora.send(recipient, recipient_pk, 500).unwrap();

    // Withdraw 300 back to a public address
    let addr = [0u8; 32];
    lumora.withdraw(300, addr).unwrap();

    // Check balance
    println!("Balance: {}", lumora.wallet.balance());

    // Check transaction history
    for tx in lumora.wallet.history() {
        println!("{tx:?}");
    }
}
```

## Using the TypeScript SDK

```bash
cd sdks/typescript
npm install
npm run build
```

```typescript
import { LumoraClient } from "@lumora/sdk";

const client = new LumoraClient("http://127.0.0.1:3030", "my-secret-key");

// Check pool status
const status = await client.status();
console.log(`Pool balance: ${status.pool_balance}`);
console.log(`Commitment count: ${status.commitment_count}`);

// Get fee estimates
const fees = await client.fees();
console.log(`Transfer fee: ${fees.transfer_fee}`);

// Stealth scan: download notes for local trial decryption
const scan = await client.stealthScan({ from_leaf_index: 0, limit: 500 });
console.log(`Found ${scan.notes.length} notes to trial-decrypt`);

// Cross-chain epoch roots
const epochs = await client.epochRoots();
console.log(`Current epoch: ${epochs.current_epoch}`);
```

See [typescript-sdk.md](typescript-sdk.md) for the full API reference.

## Using the CLI

```bash
cargo run -p lumora-cli -- run
```

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

## Cached SRS for Fast Startup

The first run generates the Structured Reference String (~130 MB, 5–9 seconds).
Subsequent runs load it from cache:

```bash
# First run: generates and caches SRS
LUMORA_DATA_DIR=./data cargo run -p lumora-rpc

# Subsequent runs: loads cached SRS in ~100ms
LUMORA_DATA_DIR=./data cargo run -p lumora-rpc
```

## Configuration

| Environment Variable    | Default          | Description                      |
| ----------------------- | ---------------- | -------------------------------- |
| `LUMORA_RPC_ADDR`       | `127.0.0.1:3030` | RPC server bind address          |
| `LUMORA_API_KEY`        | _(none)_         | API key for authentication       |
| `LUMORA_DATA_DIR`       | `./lumora_data`  | Data directory (SRS, state, WAL) |
| `LUMORA_MAX_BODY_SIZE`  | `2097152`        | Maximum request body (bytes)     |
| `LUMORA_MAX_CONCURRENT` | `128`            | Max concurrent proof requests    |
| `LUMORA_JITTER_MIN_MS`  | `50`             | Relay jitter minimum (ms)        |
| `LUMORA_JITTER_MAX_MS`  | `500`            | Relay jitter maximum (ms)        |

## Running Tests

```bash
# All library tests
cargo test --workspace --lib -- --test-threads=1

# Specific crate
cargo test -p lumora-contracts --lib

# RPC endpoint tests (26 tests)
cargo test -p lumora-rpc --lib

# TypeScript SDK tests (20 tests)
cd sdks/typescript && npm test

# With output
cargo test -p lumora-prover -- --nocapture
```

## Docker

```bash
# Build image
docker build -t lumora .

# Run
docker run -p 3030:3030 \
  -e LUMORA_API_KEY=secret \
  -e LUMORA_RPC_ADDR=0.0.0.0:3030 \
  lumora
```

## Kubernetes (Helm)

```bash
cd deploy/helm
helm install lumora lumora/ --set apiKey=my-secret-key
```

## Next Steps

- [API Guide](api-guide.md) — Full HTTP API reference (15 endpoints)
- [TypeScript SDK](typescript-sdk.md) — TypeScript client setup and reference
- [Architecture](architecture.md) — System design and data flow
- [Circuit Constraints](circuit-constraints.md) — ZK circuit details
- [Cross-Chain Privacy](cross-chain-privacy.md) — Domain-separated nullifiers and epochs
- [Stealth Addresses](stealth-addresses.md) — ECDH stealth address protocol
- [Protocol Specification](../PROTOCOL.md) — Formal protocol spec
- [Troubleshooting](troubleshooting.md) — Common issues and debugging tips
- [Security Policy](../SECURITY.md) — Vulnerability reporting
