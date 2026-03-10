# State Persistence

Lumora uses a layered persistence strategy combining a write-ahead log (WAL)
with periodic binary snapshots. This ensures crash safety, fast recovery, and
bounded storage growth.

## Strategy Overview

```
Event Stream
  │
  ├─ 1. Append to WAL (fsync)          ← every event
  ├─ 2. Apply to in-memory state
  └─ 3. Periodic snapshot + WAL truncation  ← every N events
```

On recovery:

1. Load the latest snapshot.
2. Replay any WAL entries written after the snapshot.
3. Truncate the WAL.

## Write-Ahead Log (WAL)

### File: `wal.log`

The WAL is an append-only file of length-prefixed JSON entries:

```
[4 bytes: entry_len as u32 LE][entry_len bytes: JSON-encoded WalEntry]
[4 bytes: entry_len as u32 LE][entry_len bytes: JSON-encoded WalEntry]
...
```

### WalEntry

```rust
struct WalEntry {
    seq: u64,           // Monotonic sequence number
    event: PoolEvent,   // Deposit | Transfer | Withdraw
}
```

### Crash Safety

- Each entry is independently parseable.
- `fsync` is called after every append.
- A partial trailing entry (from a crash mid-write) is detected by
  `UnexpectedEof` during the length or payload read and is safely skipped.

### Checkpoint Threshold

By default, the WAL triggers a snapshot after 100 entries. This is configurable
via `SnapshotManager::set_checkpoint_threshold()`.

## Snapshots

### File Pattern: `snapshot_NNNNNN.bin`

Each snapshot is a full binary serialization of `PrivacyPoolState`:

```
[4 bytes] Magic: 0x4C 0x4D 0x52 0x41  ("LMRA")
[4 bytes] Format version (1)
[4 bytes] Payload length
[N bytes] bincode-encoded PrivacyPoolState
[32 bytes] HMAC-SHA256 tag
```

### Metadata: `snapshot_NNNNNN.meta.json`

Each snapshot has a companion metadata file:

```json
{
  "id": 0,
  "height": 42,
  "balance": 100000,
  "event_count": 42
}
```

### Snapshot Retention

The `SnapshotManager` keeps a configurable number of snapshots (default: 3).
Older snapshots are pruned after each new snapshot is taken.

## SnapshotManager API

```rust
use lumora_contracts::snapshot::SnapshotManager;

// Open (or create) the persistence directory
let mut mgr = SnapshotManager::open(Path::new("./data"), 3)?;

// Log each event to WAL before applying
mgr.log_event(&event)?;
apply_event(&mut state, &event);

// Periodically take snapshots
if mgr.should_snapshot() {
    let meta = mgr.take_snapshot(&mut state)?;
    println!("Snapshot {} at height {}", meta.id, meta.height);
}

// On startup: recover
let (state, snapshot_id, wal_replayed) = mgr.recover()?;
```

## Binary State Format

The binary format (`save_binary` / `load_binary`) uses:

- **Magic header**: `LMRA` (4 bytes) for file type identification.
- **Version**: Format version `1` (4 bytes LE).
- **Payload**: bincode-serialized `PrivacyPoolState`.
- **HMAC**: SHA-256 HMAC over `magic + version + length + payload`.

### Advantages over JSON

| Property       | JSON                  | Binary               |
| -------------- | --------------------- | -------------------- |
| File size      | ~2–5× larger          | Compact              |
| Parse speed    | Slower (string→field) | Fast (direct decode) |
| Human readable | Yes                   | No                   |
| Integrity      | HMAC-SHA256           | HMAC-SHA256          |

## JSON State Format (Legacy)

The original JSON format is still supported for backward compatibility:

```json
{
  "version": 1,
  "payload": {
    /* PrivacyPoolState */
  },
  "hmac": "hex-encoded HMAC-SHA256"
}
```

## Incremental State Tracking

`PrivacyPoolState` tracks a `checkpoint_event_count` field (with `#[serde(default)]`
for backward compatibility). This enables:

- `pending_events()` → events since the last checkpoint
- `pending_event_count()` → count of pending events
- `mark_checkpoint()` → resets the pending boundary

The WAL and SnapshotManager use these to know which events need to be persisted.

## Epoch State Persistence

`PrivacyPoolState` includes an `EpochManager` (with `#[serde(default)]` for
backward compatibility). The epoch manager tracks:

- **Current epoch ID and start time**
- **Pending nullifiers** for the active epoch
- **Finalized epoch roots** (up to 256 retained, oldest pruned)
- **Finalized epoch ordering** for deterministic pruning

Epoch state is persisted alongside the rest of `PrivacyPoolState` in both
binary snapshots and WAL entries. On recovery, the epoch manager resumes from
the last snapshot's epoch state. New nodes or upgraded state files without epoch
data default to `EpochManager::default()` (starts a fresh epoch from the
current system time).

## Recovery Scenarios

| Scenario               | Recovery Path                               |
| ---------------------- | ------------------------------------------- |
| Clean shutdown         | Load latest snapshot (no WAL replay needed) |
| Crash after WAL append | Load snapshot + replay WAL entries          |
| Crash during snapshot  | Previous snapshot + full WAL replay         |
| No snapshot exists     | Fresh state + full WAL replay               |
| Corrupt WAL tail       | Partial entries safely skipped              |
| Both missing           | Fresh state (data loss)                     |

## Directory Layout

```
data/
├── wal.log              # Write-ahead log
├── checkpoint.bin       # Legacy WAL checkpoint (if present)
├── snapshot_000000.bin  # Snapshot #0
├── snapshot_000000.meta.json
├── snapshot_000001.bin  # Snapshot #1
├── snapshot_000001.meta.json
├── snapshot_000002.bin  # Snapshot #2 (latest)
├── snapshot_000002.meta.json
├── srs.bin              # Cached SRS parameters
└── note_store.json      # Encrypted note relay store
```
