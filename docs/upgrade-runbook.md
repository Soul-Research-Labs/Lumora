# Upgrade Runbook

Step-by-step guide for upgrading a Lumora deployment. Covers rolling upgrades,
state migrations, and nullifier V1→V2 transition.

---

## Pre-requisites

| Item                        | Check                                       |
| --------------------------- | ------------------------------------------- |
| Current version             | `curl localhost:3030/health \| jq .version` |
| State backups               | Snapshot `state/` directory                 |
| Wallet backups              | Encrypted backup of all wallets             |
| Changelog review            | Read CHANGELOG.md for breaking changes      |
| Coordinated downtime window | If nullifier migration is needed            |

---

## 1. Rolling Binary Upgrade (No State Changes)

For upgrades that only change RPC handlers, circuit optimizations, or SDK
improvements without state format changes:

```bash
# 1. Build the new binary
cargo build --release -p lumora-rpc

# 2. Verify the build
./target/release/lumora-rpc --version

# 3. Gracefully shut down the running server
# The server has a 30-second shutdown timeout for background tasks.
kill -TERM <pid>

# 4. Replace the binary and restart
cp target/release/lumora-rpc /usr/local/bin/lumora-rpc
systemctl restart lumora-rpc
```

### Health Check

```bash
curl http://localhost:3030/health
# Expect: {"status":"ok","version":"<new_version>", ...}
```

---

## 2. State Format Migration (V0 → V1)

If upgrading from a pre-envelope state file (V0) to the current versioned
format (V1 with HMAC integrity):

```bash
# 1. Stop the server
systemctl stop lumora-rpc

# 2. Back up the state directory
cp -r /var/lib/lumora/state /var/lib/lumora/state.backup

# 3. Run automatic migration
# ensure_current() detects v0 files and upgrades them in-place.
# The original file is preserved as <filename>.v0.bak
lumora migrate-state --path /var/lib/lumora/state/pool.json

# 4. Verify the migration
lumora verify-state --path /var/lib/lumora/state/pool.json

# 5. Restart
systemctl start lumora-rpc
```

**Programmatic migration** (in Rust):

```rust
use lumora_contracts::migration;

let version = migration::ensure_current("state/pool.json")?;
assert_eq!(version, 1);
```

---

## 3. Nullifier V1 → V2 Migration

This is the most complex migration. V2 nullifiers include domain separation
(chain_id + app_id) to prevent cross-chain replay attacks.

### When Is This Needed?

- Deploying Lumora to multiple chains or rollups
- Enabling cross-chain privacy features
- Moving from standalone to multi-deployment topology

### Migration Steps

```bash
# 1. Stop accepting new transactions
# Set the pool to read-only mode (reject deposits/transfers/withdrawals)

# 2. Back up everything
cp -r /var/lib/lumora /var/lib/lumora.pre-v2-backup

# 3. Dry run the nullifier migration for each wallet
lumora migrate-nullifiers \
  --wallet /path/to/wallet.json \
  --chain-id 1 \
  --app-id 42 \
  --dry-run

# 4. Review the output
# Each note shows: Leaf N: V1=<hex> → V2=<hex>
# Verify the domain parameters are correct.

# 5. Execute the migration
lumora migrate-nullifiers \
  --wallet /path/to/wallet.json \
  --chain-id 1 \
  --app-id 42

# 6. Update the on-chain nullifier set
# The pool operator must update the nullifier registry to accept
# V2 nullifiers. During the transition window, BOTH V1 and V2
# nullifiers should be accepted.

# 7. Coordinate with all wallet holders
# Each wallet holder must run the migration tool for their wallet.
# Announce the transition timeline and provide the chain_id/app_id.

# 8. After the transition window, disable V1 nullifiers
# Update the pool verifier to reject V1 nullifier proofs.

# 9. Resume normal operations
```

### Dual-Key Transition Window

During migration, the pool should accept both V1 and V2 nullifiers:

| Phase          | Duration  | V1 Accepted | V2 Accepted |
| -------------- | --------- | ----------- | ----------- |
| Pre-migration  | —         | Yes         | No          |
| Transition     | 1-2 weeks | Yes         | Yes         |
| Post-migration | —         | No          | Yes         |

### Rollback

If issues are detected during the transition:

1. Stop the server
2. Restore from `/var/lib/lumora.pre-v2-backup`
3. Restart with the old binary

---

## 4. WAL Recovery

If the server crashes, the Write-Ahead Log ensures no data loss:

```bash
# The server recovers automatically on startup:
# 1. Loads the last checkpoint snapshot
# 2. Replays all WAL entries since the checkpoint
# 3. Truncates the WAL

# To manually verify WAL integrity:
lumora verify-wal --dir /var/lib/lumora/state/
```

---

## 5. SDK Upgrade

### TypeScript

```bash
cd sdks/typescript
npm install
npm run build
npm test
```

### Python

```bash
cd sdks/python
pip install -e .
python -m pytest tests/
```

### Breaking Changes to Watch For

- `LumoraClient` constructor now accepts an optional third argument
  (`options` in TS, keyword args in Python) for timeout/retry configuration.
  **This is backward-compatible** — existing code works unchanged.
- New `LumoraConnectionError` exception type for network-level failures.
  Code catching `LumoraError` will NOT catch `LumoraConnectionError`
  (they are separate hierarchies).

---

## 6. Monitoring After Upgrade

| Metric                 | Expected                 | Alert Threshold   |
| ---------------------- | ------------------------ | ----------------- |
| `/health` status       | `"ok"`                   | Any non-ok        |
| Response latency (p99) | < 200ms                  | > 500ms           |
| Error rate             | < 0.1%                   | > 1%              |
| Pool balance           | Stable                   | Unexpected change |
| Nullifier count        | Monotonically increasing | Decrease          |

```bash
# Quick smoke test
curl -s http://localhost:3030/v1/status | jq .
curl -s http://localhost:3030/health | jq .
```

---

## Troubleshooting

| Symptom                          | Cause                         | Fix                                 |
| -------------------------------- | ----------------------------- | ----------------------------------- |
| "unrecognized state file format" | Corrupted state file          | Restore from backup                 |
| CORS errors in browser           | `LUMORA_CORS_ORIGINS` not set | Set env var (see api-guide.md)      |
| "timed out" from SDK             | Server overloaded             | Increase `timeoutMs` / `timeout`    |
| Nullifier rejected               | V1/V2 mismatch                | Check migration phase               |
| WAL replay error                 | Truncated WAL entry           | Delete WAL, restore from checkpoint |
