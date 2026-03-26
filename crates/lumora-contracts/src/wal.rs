//! Write-Ahead Log (WAL) for crash-safe state persistence.
//!
//! The WAL ensures that no committed events are lost if the node crashes
//! between processing an event and saving a full state snapshot.
//!
//! # Protocol
//!
//! 1. **Before** applying an event to in-memory state, append the event to the WAL.
//! 2. Apply the event to `PrivacyPoolState` in memory.
//! 3. Periodically checkpoint: save a full state snapshot + truncate the WAL.
//!
//! # Recovery
//!
//! On startup, if a WAL file exists:
//! 1. Load the most recent state snapshot (the checkpoint).
//! 2. Replay all WAL entries on top of that snapshot.
//! 3. Truncate the WAL.
//!
//! # On-disk format
//!
//! The WAL file is a sequence of length-prefixed JSON entries:
//!
//! ```text
//! [4B entry_len LE][entry_len bytes of JSON-encoded WalEntry]
//! [4B entry_len LE][entry_len bytes of JSON-encoded WalEntry]
//! ...
//! ```
//!
//! Each entry is independently parseable, so a partial write at the end
//! (due to crash) is detected and safely skipped.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use ff::PrimeField;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;
use crate::events::PoolEvent;
use crate::state::PrivacyPoolState;

/// Open a file for writing with restrictive permissions (0o600 on Unix).
/// WAL and checkpoint files contain transaction history and should not be
/// world-readable.
#[cfg(unix)]
fn sensitive_create(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn sensitive_create(path: &Path) -> io::Result<File> {
    File::create(path)
}

/// Open a file for appending with restrictive permissions (0o600 on Unix).
#[cfg(unix)]
fn sensitive_append(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn sensitive_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// A single WAL entry wrapping a pool event with a sequence number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalEntry {
    /// Monotonically increasing sequence number (0-based within a WAL segment).
    pub seq: u64,
    /// The pool event to replay.
    pub event: PoolEvent,
    /// Merkle root of the commitment tree *after* this event was applied.
    /// Present when written by `append_with_root`; validated during recovery.
    /// Field is optional for backward compatibility with older WAL files.
    #[serde(default)]
    pub merkle_root: Option<[u8; 32]>,
}

/// Write-ahead log handle.
///
/// Manages appending events and checkpoint/truncation.
pub struct WriteAheadLog {
    /// Path to the WAL file.
    wal_path: PathBuf,
    /// Path to the state snapshot (checkpoint) file.
    checkpoint_path: PathBuf,
    /// Current sequence number (next entry gets this seq).
    next_seq: u64,
    /// Number of entries written since last checkpoint.
    entries_since_checkpoint: u64,
    /// Threshold: auto-checkpoint after this many entries.
    checkpoint_threshold: u64,
}

/// Default number of WAL entries before auto-checkpoint.
const DEFAULT_CHECKPOINT_THRESHOLD: u64 = 100;

impl WriteAheadLog {
    /// Open or create a WAL at the given directory.
    ///
    /// The WAL file is `{dir}/wal.log` and the checkpoint is `{dir}/checkpoint.bin`.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let wal_path = dir.join("wal.log");
        let checkpoint_path = dir.join("checkpoint.bin");

        let entry_count = if wal_path.exists() {
            read_wal_entries(&wal_path)?.len() as u64
        } else {
            0
        };

        Ok(Self {
            wal_path,
            checkpoint_path,
            next_seq: entry_count,
            entries_since_checkpoint: entry_count,
            checkpoint_threshold: DEFAULT_CHECKPOINT_THRESHOLD,
        })
    }

    /// Set the auto-checkpoint threshold (number of entries).
    pub fn set_checkpoint_threshold(&mut self, threshold: u64) {
        self.checkpoint_threshold = threshold;
    }

    /// Append an event to the WAL. Flushes + fsyncs to guarantee durability.
    pub fn append(&mut self, event: &PoolEvent) -> io::Result<()> {
        self.append_impl(event, None)
    }

    /// Append an event together with the Merkle root *after* applying the event.
    ///
    /// During recovery the stored root is compared to the replayed root; a
    /// mismatch is returned as an `InvalidData` error so the operator can
    /// take corrective action before the node accepts further transactions.
    pub fn append_with_root(&mut self, event: &PoolEvent, root: pallas::Base) -> io::Result<()> {
        self.append_impl(event, Some(root.to_repr()))
    }

    fn append_impl(&mut self, event: &PoolEvent, merkle_root: Option<[u8; 32]>) -> io::Result<()> {
        let entry = WalEntry {
            seq: self.next_seq,
            event: event.clone(),
            merkle_root,
        };

        let json = serde_json::to_vec(&entry)
            .map_err(io::Error::other)?;
        let len = json.len() as u32;

        let file = sensitive_append(&self.wal_path)?;
        let mut writer = BufWriter::new(&file);
        writer.write_all(&len.to_le_bytes())?;
        writer.write_all(&json)?;
        writer.flush()?;
        file.sync_all()?;

        self.next_seq += 1;
        self.entries_since_checkpoint += 1;
        Ok(())
    }

    /// Returns true if the number of entries since last checkpoint
    /// meets or exceeds the threshold.
    pub fn needs_checkpoint(&self) -> bool {
        self.entries_since_checkpoint >= self.checkpoint_threshold
    }

    /// Write a full state checkpoint and truncate the WAL.
    ///
    /// This saves `state` using the binary format, marks the checkpoint
    /// boundary in state, then clears the WAL file.
    pub fn checkpoint(&mut self, state: &mut PrivacyPoolState) -> io::Result<()> {
        // Mark the state so pending_events() resets.
        state.mark_checkpoint();

        // Save the state snapshot atomically.
        state.save_binary(&self.checkpoint_path)?;

        // Truncate the WAL file (with restrictive permissions).
        sensitive_create(&self.wal_path)?;

        self.entries_since_checkpoint = 0;
        Ok(())
    }

    /// Recover state from the most recent checkpoint + any pending WAL entries.
    ///
    /// Returns `(state, replayed_count)` — the recovered state and how many
    /// WAL entries were replayed on top of the checkpoint.
    ///
    /// If no checkpoint exists, returns a fresh `PrivacyPoolState`.
    pub fn recover(&mut self) -> io::Result<(PrivacyPoolState, u64)> {
        let mut state = if self.checkpoint_path.exists() {
            PrivacyPoolState::load_binary(&self.checkpoint_path)?
        } else {
            PrivacyPoolState::new()
        };

        let entries = if self.wal_path.exists() {
            read_wal_entries(&self.wal_path)?
        } else {
            Vec::new()
        };

        let replayed = entries.len() as u64;
        for entry in &entries {
            replay_event(&mut state, &entry.event)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("WAL replay error at seq {}: {e}", entry.seq)))?;
            // If the entry records the expected post-event root, verify it.
            if let Some(root_bytes) = entry.merkle_root {
                let expected: Option<pallas::Base> = pallas::Base::from_repr(root_bytes).into();
                if let Some(expected_root) = expected {
                    let actual_root = state.current_root();
                    if actual_root != expected_root {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "WAL replay seq {}: Merkle root mismatch \
                                 (expected {:?}, got {:?})",
                                entry.seq, expected_root, actual_root
                            ),
                        ));
                    }
                }
            }
        }

        // After recovery, reset the WAL.
        self.next_seq = 0;
        self.entries_since_checkpoint = 0;
        if self.wal_path.exists() {
            sensitive_create(&self.wal_path)?;
        }

        Ok((state, replayed))
    }

    /// Number of entries written since the last checkpoint.
    pub fn entries_since_checkpoint(&self) -> u64 {
        self.entries_since_checkpoint
    }

    /// Path to the WAL file.
    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    /// Path to the checkpoint file.
    pub fn checkpoint_path(&self) -> &Path {
        &self.checkpoint_path
    }

    /// Recover by replaying WAL entries onto an existing state.
    ///
    /// Unlike `recover()`, this takes an already-loaded state (e.g. from a
    /// snapshot) and replays WAL entries on top of it. Resets WAL after replay.
    pub fn recover_onto(&mut self, mut state: PrivacyPoolState) -> io::Result<(PrivacyPoolState, u64)> {
        let entries = if self.wal_path.exists() {
            read_wal_entries(&self.wal_path)?
        } else {
            Vec::new()
        };

        let replayed = entries.len() as u64;
        for entry in &entries {
            replay_event(&mut state, &entry.event)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("WAL replay (onto) error at seq {}: {e}", entry.seq)))?;
            if let Some(root_bytes) = entry.merkle_root {
                let expected: Option<pallas::Base> = pallas::Base::from_repr(root_bytes).into();
                if let Some(expected_root) = expected {
                    let actual_root = state.current_root();
                    if actual_root != expected_root {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "WAL replay (onto) seq {}: Merkle root mismatch \
                                 (expected {:?}, got {:?})",
                                entry.seq, expected_root, actual_root
                            ),
                        ));
                    }
                }
            }
        }

        self.next_seq = 0;
        self.entries_since_checkpoint = 0;
        if self.wal_path.exists() {
            sensitive_create(&self.wal_path)?;
        }

        Ok((state, replayed))
    }
}

/// Read all valid WAL entries from a WAL file.
///
/// A partial/corrupt trailing entry (from a crash mid-write) is silently
/// skipped — this is the standard WAL recovery behaviour.
fn read_wal_entries(path: &Path) -> io::Result<Vec<WalEntry>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut entries = Vec::new();

    loop {
        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        // Read the JSON payload.
        let mut json_buf = vec![0u8; len];
        match reader.read_exact(&mut json_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Partial entry at end — crash during write. Safe to skip.
                break;
            }
            Err(e) => return Err(e),
        }

        // Parse the entry — a corrupt entry terminates reading.
        match serde_json::from_slice::<WalEntry>(&json_buf) {
            Ok(entry) => entries.push(entry),
            Err(_) => break,
        }
    }

    Ok(entries)
}

/// Replay a single event onto state, mirroring the same state transitions
/// that the original execution performed.
///
/// Returns `Err(ContractError::PoolBalanceOverflow)` if a deposit would
/// overflow the pool balance counter during replay (indicates data corruption).
pub fn replay_event(state: &mut PrivacyPoolState, event: &PoolEvent) -> Result<(), ContractError> {
    match event {
        PoolEvent::Deposit {
            commitment, amount, ..
        } => {
            state.insert_commitment(*commitment);
            state.pool_balance = state
                .pool_balance
                .checked_add(*amount)
                .ok_or(ContractError::PoolBalanceOverflow)?;
            state.emit_event(event.clone());
        }
        PoolEvent::Transfer {
            nullifiers,
            output_commitments,
            ..
        } => {
            state.replay_transfer_event(nullifiers, output_commitments);
            state.emit_event(event.clone());
        }
        PoolEvent::Withdraw {
            nullifiers,
            change_commitments,
            amount,
            ..
        } => {
            state.replay_withdraw_event(nullifiers, change_commitments, *amount)?;
            state.emit_event(event.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::pallas;
    use std::env::temp_dir;

    fn test_dir(name: &str) -> PathBuf {
        let dir = temp_dir().join(format!("lumora_wal_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn wal_append_and_recover() {
        let dir = test_dir("append_recover");
        let mut wal = WriteAheadLog::open(&dir).unwrap();

        // Append a deposit event.
        let event = PoolEvent::Deposit {
            commitment: pallas::Base::from(42u64),
            amount: 1000,
            leaf_index: 0,
        };
        wal.append(&event).unwrap();

        // Append a transfer event.
        let event2 = PoolEvent::Transfer {
            nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
            output_commitments: [pallas::Base::from(3u64), pallas::Base::from(4u64)],
            leaf_indices: [1, 2],
            transparency_memo: None,
            domain_chain_id: None,
            domain_app_id: None,
        };
        wal.append(&event2).unwrap();

        assert_eq!(wal.entries_since_checkpoint(), 2);

        // Simulate crash: drop the WAL and re-open + recover.
        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();
        let (state, replayed) = wal2.recover().unwrap();

        assert_eq!(replayed, 2);
        assert_eq!(state.commitment_count(), 3); // 1 deposit + 2 transfer outputs
        assert_eq!(state.pool_balance(), 1000);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_checkpoint_truncates() {
        let dir = test_dir("checkpoint");
        let mut wal = WriteAheadLog::open(&dir).unwrap();

        let mut state = PrivacyPoolState::new();
        let event = PoolEvent::Deposit {
            commitment: pallas::Base::from(10u64),
            amount: 500,
            leaf_index: 0,
        };
        wal.append(&event).unwrap();
        replay_event(&mut state, &event).unwrap();
        wal.checkpoint(&mut state).unwrap();
        assert_eq!(wal.entries_since_checkpoint(), 0);

        // WAL file should now be empty.
        let wal_data = fs::read(wal.wal_path()).unwrap();
        assert!(wal_data.is_empty());

        // Recover from checkpoint — should get the same state, 0 replayed.
        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();
        let (recovered, replayed) = wal2.recover().unwrap();
        assert_eq!(replayed, 0);
        assert_eq!(recovered.pool_balance(), 500);
        assert_eq!(recovered.commitment_count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_recover_with_checkpoint_plus_entries() {
        let dir = test_dir("checkpoint_plus_entries");
        let mut wal = WriteAheadLog::open(&dir).unwrap();

        let mut state = PrivacyPoolState::new();

        // First deposit + checkpoint.
        let e1 = PoolEvent::Deposit {
            commitment: pallas::Base::from(10u64),
            amount: 500,
            leaf_index: 0,
        };
        wal.append(&e1).unwrap();
        replay_event(&mut state, &e1).unwrap();
        wal.checkpoint(&mut state).unwrap();

        // Second deposit (not checkpointed — simulates crash).
        let e2 = PoolEvent::Deposit {
            commitment: pallas::Base::from(20u64),
            amount: 300,
            leaf_index: 1,
        };
        wal.append(&e2).unwrap();

        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();
        let (recovered, replayed) = wal2.recover().unwrap();

        assert_eq!(replayed, 1); // only e2 was in the WAL
        assert_eq!(recovered.pool_balance(), 800); // 500 + 300
        assert_eq!(recovered.commitment_count(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_partial_entry_skipped() {
        let dir = test_dir("partial_entry");
        let mut wal = WriteAheadLog::open(&dir).unwrap();

        let event = PoolEvent::Deposit {
            commitment: pallas::Base::from(99u64),
            amount: 100,
            leaf_index: 0,
        };
        wal.append(&event).unwrap();

        // Append garbage (partial entry) at end of WAL file.
        let mut file = OpenOptions::new()
            .append(true)
            .open(wal.wal_path())
            .unwrap();
        // Write a length prefix claiming 1000 bytes but only write 5.
        file.write_all(&1000u32.to_le_bytes()).unwrap();
        file.write_all(b"trash").unwrap();
        drop(file);

        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();
        let (recovered, replayed) = wal2.recover().unwrap();

        // Only the first valid entry should be recovered.
        assert_eq!(replayed, 1);
        assert_eq!(recovered.pool_balance(), 100);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_auto_checkpoint_threshold() {
        let dir = test_dir("threshold");
        let mut wal = WriteAheadLog::open(&dir).unwrap();
        wal.set_checkpoint_threshold(3);

        for i in 0..3 {
            let event = PoolEvent::Deposit {
                commitment: pallas::Base::from(i as u64),
                amount: 10,
                leaf_index: i as u64,
            };
            wal.append(&event).unwrap();
        }

        assert!(wal.needs_checkpoint());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_empty_recover_returns_fresh_state() {
        let dir = test_dir("empty_recover");
        let mut wal = WriteAheadLog::open(&dir).unwrap();
        let (state, replayed) = wal.recover().unwrap();
        assert_eq!(replayed, 0);
        assert_eq!(state.pool_balance(), 0);
        assert_eq!(state.commitment_count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_recover_onto_existing_state() {
        let dir = test_dir("recover_onto");
        let mut wal = WriteAheadLog::open(&dir).unwrap();

        let event = PoolEvent::Deposit {
            commitment: pallas::Base::from(77u64),
            amount: 200,
            leaf_index: 1,
        };
        wal.append(&event).unwrap();

        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();

        // Pre-populate a state with one commitment.
        let mut base_state = PrivacyPoolState::new();
        base_state.insert_commitment(pallas::Base::from(55u64));
        base_state.pool_balance = 100;

        let (state, replayed) = wal2.recover_onto(base_state).unwrap();
        assert_eq!(replayed, 1);
        assert_eq!(state.pool_balance(), 300); // 100 + 200
        assert_eq!(state.commitment_count(), 2); // 1 pre-existing + 1 replayed

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_withdraw_event_replay() {
        let dir = test_dir("withdraw_replay");
        let mut wal = WriteAheadLog::open(&dir).unwrap();

        let deposit = PoolEvent::Deposit {
            commitment: pallas::Base::from(1u64),
            amount: 1000,
            leaf_index: 0,
        };
        wal.append(&deposit).unwrap();

        let withdraw = PoolEvent::Withdraw {
            nullifiers: [pallas::Base::from(10u64), pallas::Base::from(11u64)],
            change_commitments: [pallas::Base::from(12u64), pallas::Base::from(13u64)],
            amount: 400,
            recipient: [0xABu8; 32],
            leaf_indices: [1, 2],
            transparency_memo: None,
            domain_chain_id: None,
            domain_app_id: None,
        };
        wal.append(&withdraw).unwrap();

        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();
        let (state, replayed) = wal2.recover().unwrap();
        assert_eq!(replayed, 2);
        assert_eq!(state.pool_balance(), 600); // 1000 - 400

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wal_multiple_checkpoints() {
        let dir = test_dir("multi_checkpoint");
        let mut wal = WriteAheadLog::open(&dir).unwrap();
        let mut state = PrivacyPoolState::new();

        for i in 0..3u64 {
            let event = PoolEvent::Deposit {
                commitment: pallas::Base::from(i),
                amount: 100,
                leaf_index: i,
            };
            wal.append(&event).unwrap();
            replay_event(&mut state, &event).unwrap();
            wal.checkpoint(&mut state).unwrap();
        }

        drop(wal);
        let mut wal2 = WriteAheadLog::open(&dir).unwrap();
        let (recovered, replayed) = wal2.recover().unwrap();
        assert_eq!(replayed, 0);
        assert_eq!(recovered.pool_balance(), 300);
        assert_eq!(recovered.commitment_count(), 3);

        let _ = fs::remove_dir_all(&dir);
    }
}
