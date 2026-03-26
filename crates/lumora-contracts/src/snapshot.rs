//! Snapshot + WAL recovery manager.
//!
//! Combines periodic binary snapshots with incremental WAL replay to provide
//! fast startup, bounded WAL growth, and snapshot history for rollback.
//!
//! # Strategy
//!
//! 1. On each event, append to WAL.
//! 2. When `wal.needs_checkpoint()`, take a new numbered snapshot and truncate the WAL.
//! 3. On recovery, load the latest snapshot and replay any trailing WAL entries.
//! 4. Old snapshots beyond `max_snapshots` are pruned.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::events::PoolEvent;
use crate::state::PrivacyPoolState;
use crate::wal::WriteAheadLog;

/// Snapshot metadata stored alongside each snapshot file.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMeta {
    /// Monotonically increasing snapshot ID.
    pub id: u64,
    /// Pool height (commitment count) at the time of the snapshot.
    pub height: u64,
    /// Pool balance at the time of the snapshot.
    pub balance: u64,
    /// Number of events in the event log at snapshot time.
    pub event_count: usize,
}

/// Manages snapshots + WAL for crash-safe state persistence.
pub struct SnapshotManager {
    /// Base directory for all persistence files.
    dir: PathBuf,
    /// The write-ahead log.
    wal: WriteAheadLog,
    /// Maximum number of snapshot files to retain.
    max_snapshots: usize,
    /// Current snapshot ID counter.
    next_snapshot_id: u64,
}

impl SnapshotManager {
    /// Open or create a snapshot manager at the given directory.
    ///
    /// Scans for existing snapshots to set the ID counter and loads the WAL.
    pub fn open(dir: &Path, max_snapshots: usize) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let wal = WriteAheadLog::open(dir)?;

        let existing = list_snapshots(dir)?;
        let next_snapshot_id = existing.last().map(|(id, _)| id + 1).unwrap_or(0);

        Ok(Self {
            dir: dir.to_path_buf(),
            wal,
            max_snapshots: max_snapshots.max(1),
            next_snapshot_id,
        })
    }

    /// Append an event to the WAL for durability.
    pub fn log_event(&mut self, event: &PoolEvent) -> io::Result<()> {
        self.wal.append(event)
    }

    /// Returns true if the WAL has grown enough to merit a snapshot.
    pub fn should_snapshot(&self) -> bool {
        self.wal.needs_checkpoint()
    }

    /// Take a numbered snapshot: save state, write metadata, truncate WAL,
    /// and prune old snapshots beyond `max_snapshots`.
    pub fn take_snapshot(&mut self, state: &mut PrivacyPoolState) -> io::Result<SnapshotMeta> {
        let id = self.next_snapshot_id;
        let snap_path = self.snapshot_path(id);
        let meta_path = self.meta_path(id);

        // Mark the state checkpoint boundary.
        state.mark_checkpoint();

        // Save binary snapshot.
        state.save_binary(&snap_path)?;

        // Save metadata.
        let meta = SnapshotMeta {
            id,
            height: state.commitment_count(),
            balance: state.pool_balance(),
            event_count: state.events().len(),
        };
        let meta_json = serde_json::to_vec_pretty(&meta)
            .map_err(io::Error::other)?;
        fs::write(&meta_path, meta_json)?;

        // Truncate WAL (don't call wal.checkpoint which would write its own file).
        let wal_file_path = self.dir.join("wal.log");
        fs::File::create(&wal_file_path)?;
        // Reset WAL internal counters by re-opening.
        self.wal = WriteAheadLog::open(&self.dir)?;

        self.next_snapshot_id = id + 1;

        // Prune old snapshots.
        self.prune_old_snapshots()?;

        Ok(meta)
    }

    /// Recover state from the latest snapshot + any WAL entries.
    ///
    /// Returns `(state, snapshot_id, wal_entries_replayed)`.
    /// If no snapshot exists, returns a fresh state.
    pub fn recover(&mut self) -> io::Result<(PrivacyPoolState, Option<u64>, u64)> {
        let snapshots = list_snapshots(&self.dir)?;

        let (state, snap_id) = if let Some((id, path)) = snapshots.last() {
            let state = PrivacyPoolState::load_binary(path)?;
            (state, Some(*id))
        } else {
            // Also check the WAL's own checkpoint file (from earlier versions).
            let checkpoint_path = self.dir.join("checkpoint.bin");
            if checkpoint_path.exists() {
                let state = PrivacyPoolState::load_binary(&checkpoint_path)?;
                (state, None)
            } else {
                (PrivacyPoolState::new(), None)
            }
        };

        // Replay WAL on top of snapshot.
        let (state, replayed) = self.wal.recover_onto(state)?;

        Ok((state, snap_id, replayed))
    }

    /// List all snapshot metadata, newest last.
    pub fn list_snapshots(&self) -> io::Result<Vec<SnapshotMeta>> {
        let snaps = list_snapshots(&self.dir)?;
        let mut metas = Vec::new();
        for (_, path) in &snaps {
            let meta_path = path.with_extension("meta.json");
            if meta_path.exists() {
                let data = fs::read(&meta_path)?;
                if let Ok(meta) = serde_json::from_slice::<SnapshotMeta>(&data) {
                    metas.push(meta);
                }
            }
        }
        Ok(metas)
    }

    /// The number of WAL entries since the last snapshot/checkpoint.
    pub fn pending_wal_entries(&self) -> u64 {
        self.wal.entries_since_checkpoint()
    }

    /// Set the WAL checkpoint threshold (number of entries before auto-snapshot).
    pub fn set_checkpoint_threshold(&mut self, threshold: u64) {
        self.wal.set_checkpoint_threshold(threshold);
    }

    // --- Internal helpers ---

    fn snapshot_path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("snapshot_{id:06}.bin"))
    }

    fn meta_path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("snapshot_{id:06}.meta.json"))
    }

    fn prune_old_snapshots(&self) -> io::Result<()> {
        let snaps = list_snapshots(&self.dir)?;
        if snaps.len() > self.max_snapshots {
            let to_remove = snaps.len() - self.max_snapshots;
            for (id, path) in snaps.iter().take(to_remove) {
                let _ = fs::remove_file(path);
                let _ = fs::remove_file(self.meta_path(*id));
            }
        }
        Ok(())
    }
}

/// List snapshot files in the directory, sorted by ID ascending.
fn list_snapshots(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut snaps = Vec::new();
    if !dir.exists() {
        return Ok(snaps);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Match pattern: snapshot_000042.bin
        if let Some(rest) = name_str.strip_prefix("snapshot_") {
            if let Some(id_str) = rest.strip_suffix(".bin") {
                if let Ok(id) = id_str.parse::<u64>() {
                    snaps.push((id, entry.path()));
                }
            }
        }
    }
    snaps.sort_by_key(|(id, _)| *id);
    Ok(snaps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::replay_event;
    use pasta_curves::pallas;
    use std::env::temp_dir;

    fn test_dir(name: &str) -> PathBuf {
        let dir = temp_dir().join(format!("lumora_snap_test_{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn deposit_event(commitment_val: u64, amount: u64, idx: u64) -> PoolEvent {
        PoolEvent::Deposit {
            commitment: pallas::Base::from(commitment_val),
            amount,
            leaf_index: idx,
        }
    }

    #[test]
    fn snapshot_and_recover() {
        let dir = test_dir("snap_recover");
        let mut mgr = SnapshotManager::open(&dir, 3).unwrap();

        let mut state = PrivacyPoolState::new();
        let event = deposit_event(42, 1000, 0);
        mgr.log_event(&event).unwrap();
        replay_event(&mut state, &event).unwrap();

        let meta = mgr.take_snapshot(&mut state).unwrap();
        assert_eq!(meta.id, 0);
        assert_eq!(meta.balance, 1000);
        assert_eq!(meta.height, 1);

        // Add one more event after snapshot (in WAL only).
        let event2 = deposit_event(43, 500, 1);
        mgr.log_event(&event2).unwrap();
        replay_event(&mut state, &event2).unwrap();

        // Simulate crash: re-open.
        drop(mgr);
        let mut mgr2 = SnapshotManager::open(&dir, 3).unwrap();
        let (recovered, snap_id, replayed) = mgr2.recover().unwrap();

        assert_eq!(snap_id, Some(0));
        assert_eq!(replayed, 1); // 1 WAL entry after snapshot
        assert_eq!(recovered.pool_balance(), 1500);
        assert_eq!(recovered.commitment_count(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_pruning() {
        let dir = test_dir("snap_prune");
        let mut mgr = SnapshotManager::open(&dir, 2).unwrap(); // Keep max 2

        let mut state = PrivacyPoolState::new();

        // Take 4 snapshots.
        for i in 0..4u64 {
            let event = deposit_event(i + 10, 100, i);
            mgr.log_event(&event).unwrap();
            replay_event(&mut state, &event).unwrap();
            mgr.take_snapshot(&mut state).unwrap();
        }

        // Only 2 snapshots should remain (IDs 2 and 3).
        let snaps = list_snapshots(&dir).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].0, 2);
        assert_eq!(snaps[1].0, 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_fresh_no_snapshot() {
        let dir = test_dir("snap_fresh");
        let mut mgr = SnapshotManager::open(&dir, 3).unwrap();

        let (state, snap_id, replayed) = mgr.recover().unwrap();
        assert!(snap_id.is_none());
        assert_eq!(replayed, 0);
        assert_eq!(state.pool_balance(), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_snapshot_metadata() {
        let dir = test_dir("snap_list");
        let mut mgr = SnapshotManager::open(&dir, 5).unwrap();

        let mut state = PrivacyPoolState::new();
        for i in 0..3u64 {
            let event = deposit_event(i + 100, 200 * (i + 1), i);
            mgr.log_event(&event).unwrap();
            replay_event(&mut state, &event).unwrap();
            mgr.take_snapshot(&mut state).unwrap();
        }

        let metas = mgr.list_snapshots().unwrap();
        assert_eq!(metas.len(), 3);
        assert_eq!(metas[0].id, 0);
        assert_eq!(metas[2].id, 2);
        assert_eq!(metas[2].height, 3);

        let _ = fs::remove_dir_all(&dir);
    }
}
