# Troubleshooting

Common issues, debugging tips, and solutions for Lumora development and deployment.

## Build Issues

### `error[E0658]: use of unstable library feature`

**Cause**: Rust version too old.

**Fix**: Update to Rust 1.75+:

```bash
rustup update stable
rustc --version  # should be >= 1.75.0
```

### Compilation takes too long / runs out of memory

**Cause**: Halo2 circuit compilation is resource-intensive.

**Fix**:

- Ensure at least 4 GB RAM available.
- Use `cargo build --release` (debug builds use more memory).
- Build a single crate: `cargo build -p lumora-rpc`.
- Close memory-heavy applications during compilation.

### `error: failed to resolve: use of undeclared crate`

**Cause**: Missing dependency or wrong workspace member.

**Fix**:

```bash
# Ensure you're in the workspace root
cd lumora/
cargo check --workspace
```

### TypeScript SDK build fails

```bash
cd sdks/typescript
rm -rf node_modules dist
npm install
npm run build
```

Requires Node.js 18+:

```bash
node --version  # should be >= 18.0.0
```

---

## Server Startup Issues

### Cold start takes 5–9 seconds

**Cause**: First-time SRS (Structured Reference String) generation.

**Expected**: This is normal. The SRS is cached after the first run:

```bash
LUMORA_DATA_DIR=./data cargo run -p lumora-rpc
# First run: ~5-9s (SRS generation)
# Second run: ~0.1s (cached SRS load)
```

### `Address already in use` error

**Cause**: Another process is using port 3030.

**Fix**:

```bash
# Find the process using port 3030
lsof -i :3030

# Use a different port
LUMORA_RPC_ADDR=127.0.0.1:3031 cargo run -p lumora-rpc
```

### Server starts but requests return 401

**Cause**: API key mismatch.

**Fix**: Ensure the `X-API-Key` header matches the `LUMORA_API_KEY` environment
variable:

```bash
# Start server
LUMORA_API_KEY=my-secret-key cargo run -p lumora-rpc

# Use matching key in requests
curl -H "X-API-Key: my-secret-key" http://127.0.0.1:3030/v1/status
```

The `/health` endpoint does not require authentication:

```bash
curl http://127.0.0.1:3030/health
```

---

## Proof Generation Issues

### Proof generation fails with "invalid witness"

**Cause**: Input notes don't match the current Merkle tree state.

**Debugging**:

1. Check that the Merkle root is current:
   ```bash
   curl -H "X-API-Key: key" http://127.0.0.1:3030/v1/status
   ```
2. Verify the note commitment exists in the tree.
3. Ensure the spending key matches the note's owner field.
4. Check that nullifiers haven't already been spent:
   ```bash
   curl -s -X POST http://127.0.0.1:3030/v1/nullifier \
     -H "Content-Type: application/json" \
     -H "X-API-Key: key" \
     -d '{"nullifier":"aabb..."}'
   ```

### Proof generation is slow (>10 seconds)

**Cause**: Running in debug mode or insufficient resources.

**Fix**:

- Always use `--release` for proof generation: `cargo run --release -p lumora-rpc`
- Ensure at least 512 MB free RAM during proof generation.
- Check CPU utilization — proof generation is single-threaded per request.

### "Batch verification failed" on `/v1/batch-verify`

**Cause**: One or more proofs in the batch are invalid.

**Debugging**: The response includes per-proof results:

```json
{
  "results": [true, false, true],
  "all_valid": false
}
```

Check the failing proof (index 1 in this example) individually.

---

## State & Persistence Issues

### WAL corruption after crash

**Cause**: Incomplete WAL write during an unexpected crash.

**Recovery**: Lumora's WAL is designed for crash safety. On restart, it:

1. Reads the WAL from the beginning.
2. Skips incomplete (partially-written) entries.
3. Replays complete entries to rebuild state.

If the WAL is unrecoverable:

```bash
# Fall back to the latest snapshot
ls lumora_data/snapshot_*.bin
# The node will load the most recent valid snapshot
```

### State divergence between nodes

**Cause**: Network partition or Byzantine peer.

**Debugging**:

1. Compare sync status between nodes:
   ```bash
   curl -H "X-API-Key: key" http://node-a:3030/v1/sync/status
   curl -H "X-API-Key: key" http://node-b:3030/v1/sync/status
   ```
2. Check if heights and Merkle roots match.
3. If diverged, use `POST /v1/sync/events` to identify the fork point.

### Snapshot HMAC verification fails

**Cause**: Snapshot data was modified or the HMAC key changed.

**Fix**:

- Ensure the same `LUMORA_DATA_DIR` and HMAC key are used.
- If the snapshot is corrupted, delete it and let the node rebuild from WAL.

---

## Cross-Chain & Epoch Issues

### Epoch roots not appearing on `/v1/epoch-roots`

**Cause**: The epoch finalization loop hasn't run yet, or no commitments exist.

**Debugging**:

1. Wait at least 60 seconds (default epoch interval).
2. Check that deposits/transfers have been made (empty tree → no epoch roots).
3. Verify the server was started with background tasks enabled.

### V2 nullifier rejected

**Cause**: Domain chain ID or app ID mismatch.

**Fix**: Ensure `domain_chain_id` and `domain_app_id` match the server's
configuration:

```typescript
await client.transfer({
  // ...
  domain_chain_id: 1, // must match server configuration
  domain_app_id: 0,
});
```

---

## TypeScript SDK Issues

### `fetch is not defined`

**Cause**: Running in Node.js < 18 (which lacks global `fetch`).

**Fix**: Upgrade to Node.js 18+ or use a polyfill:

```bash
node --version  # ensure >= 18.0.0
```

### `LumoraError: Lumora API error (413)`

**Cause**: Request body exceeds the server's `LUMORA_MAX_BODY_SIZE` (default 2 MB).

**Fix**:

- Reduce the request payload size.
- Increase the server limit: `LUMORA_MAX_BODY_SIZE=4194304 cargo run -p lumora-rpc`

### `LumoraError: Lumora API error (429)`

**Cause**: Exceeded the concurrent request limit (`LUMORA_MAX_CONCURRENT`, default 128).

**Fix**:

- Reduce client concurrency.
- Increase the server limit: `LUMORA_MAX_CONCURRENT=256 cargo run -p lumora-rpc`

### Stealth scan returns empty results

**Possible causes**:

1. No notes exist in the specified range. Check `from_leaf_index` and `limit`.
2. The pool is empty (no deposits have been made).
3. The `from_leaf_index` is past the last note.

**Debugging**:

```typescript
// Check pool status first
const status = await client.status();
console.log(`Commitment count: ${status.commitment_count}`);

// Scan from the beginning
const scan = await client.stealthScan({ from_leaf_index: 0, limit: 10 });
console.log(`Notes found: ${scan.count}`);
```

---

## Testing Issues

### Tests fail with `--test-threads=1`

**Cause**: Some tests share global state (SRS parameters) and must run single-threaded.

**Fix**: Always run Lumora tests with `--test-threads=1`:

```bash
cargo test --workspace --lib -- --test-threads=1
```

### Specific test crate fails

**Fix**: Run the individual crate's tests to get detailed output:

```bash
cargo test -p lumora-prover --lib -- --test-threads=1 --nocapture
```

### TypeScript tests fail

```bash
cd sdks/typescript
npm install
npm run build   # compile first
npm test        # run 20 tests
```

If tests fail with import errors, ensure the build step completed successfully.

---

## Performance Issues

### High memory usage (>1 GB)

**Cause**: SRS parameters and proving keys are memory-intensive.

**Expected**: A running node uses ~300-400 MB. If significantly higher:

- Check for memory leaks in custom extensions.
- Ensure you're running `--release` (debug builds use more memory).
- Monitor with `htop` or Activity Monitor.

### Slow API responses (>1 second) for non-proof endpoints

**Cause**: Lock contention on the shared `Arc<RwLock<LumoraNode>>`.

**Debugging**:

1. Check if proof generation is in progress (3-6 seconds, holds write lock).
2. Use `/health` to verify the server is responsive.
3. Check `LUMORA_MAX_CONCURRENT` — lower values reduce contention.

---

## FAQ

**Q: Is Lumora audited?**
A: No. Lumora is pre-1.0 and has not undergone a formal security audit. Do not
use in production with real funds. See [SECURITY.md](../SECURITY.md).

**Q: Can I use Lumora without an API key?**
A: Only the `/health` endpoint works without an API key. All `/v1/*` endpoints
require the `X-API-Key` header matching `LUMORA_API_KEY`.

**Q: How do I back up my wallet?**
A: Save the BIP39 mnemonic (24 words) securely. The wallet can be reconstructed
from the mnemonic. Additionally, the encrypted wallet file can be backed up.

**Q: What happens if I lose my spending key?**
A: All unspent notes are unrecoverable. There is no recovery mechanism beyond
the BIP39 mnemonic. Keep backups of your mnemonic in a secure location.

**Q: Can I run multiple Lumora nodes?**
A: Yes. Nodes synchronize via the state delta protocol. Set different data
directories and RPC addresses for each node.

**Q: What is the maximum pool capacity?**
A: The depth-32 Merkle tree supports up to 4.3 billion (2^32) note commitments.

**Q: How do stealth addresses work?**
A: See [Stealth Addresses](stealth-addresses.md) for the full ECDH protocol.

**Q: What's the difference between V1 and V2 nullifiers?**
A: V2 nullifiers include a domain tag that prevents cross-chain replay. See
[Cross-Chain Privacy](cross-chain-privacy.md).

## Related Documents

- [Getting Started](getting-started.md) — Build and run instructions
- [Deployment](../DEPLOYMENT.md) — Production deployment guide
- [Contributing](../CONTRIBUTING.md) — Development workflow and debugging tips
- [Security](../SECURITY.md) — Vulnerability reporting
- [Benchmarks](../BENCHMARKS.md) — Performance reference
