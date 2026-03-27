//! On-chain state management for the Lumora privacy pool.
//!
//! Tracks:
//! - The note commitment Merkle tree (on-chain: root + full tree for witness generation)
//! - The nullifier registry (spent note markers)
//! - Historical Merkle roots (for proof verification against recent roots)
//! - Pool balance (total shielded value)

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use pasta_curves::pallas;
use serde::{Serialize, Deserialize};
use subtle::ConstantTimeEq;

use crate::epoch::EpochManager;
use crate::error::ContractError;
use crate::events::{EventLog, PoolEvent};
use lumora_tree::IncrementalMerkleTree;

/// A nullifier entry with constant-time equality comparison to prevent
/// timing side-channel leakage during nullifier lookups.
///
/// `Hash` uses the standard byte hash (safe — hashing is one-way and doesn't
/// leak information about which bucket an entry lives in). `Eq` uses
/// `subtle::ConstantTimeEq` so that the final equality check within a
/// `HashSet` bucket does not reveal information via timing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct NullifierEntry(pub [u8; 32]);

impl PartialEq for NullifierEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for NullifierEntry {}

impl Hash for NullifierEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Maximum number of historical roots to retain.
/// Proofs can reference any root in this window, allowing for
/// slight delays between proof generation and on-chain submission.
pub const ROOT_HISTORY_SIZE: usize = 256;

/// The on-chain state of the Lumora privacy pool.
#[derive(Serialize, Deserialize)]
pub struct PrivacyPoolState {
    /// The note commitment Merkle tree.
    pub(crate) tree: IncrementalMerkleTree,
    /// Set of spent nullifiers (prevents double-spend).
    /// Uses `NullifierEntry` for constant-time equality comparison.
    pub(crate) nullifiers: HashSet<NullifierEntry>,
    /// Rolling history of Merkle roots.
    /// New roots are pushed to the back; old ones fall off.
    #[serde(with = "lumora_primitives::serde_field::base_vec")]
    pub(crate) root_history: Vec<pallas::Base>,
    /// Total shielded balance in the pool (in base units).
    pub(crate) pool_balance: u64,
    /// Append-only event log for auditing.
    pub(crate) event_log: EventLog,
    /// Number of events at the last checkpoint (used for incremental persistence).
    #[serde(default)]
    pub(crate) checkpoint_event_count: usize,
    /// Epoch-based nullifier partitioning for cross-chain sync.
    #[serde(default)]
    pub(crate) epoch_manager: EpochManager,
}

impl PrivacyPoolState {
    /// Create a fresh, empty privacy pool.
    pub fn new() -> Self {
        let mut tree = IncrementalMerkleTree::new();
        let initial_root = tree.root();
        Self {
            tree,
            nullifiers: HashSet::new(),
            root_history: vec![initial_root],
            pool_balance: 0,
            event_log: EventLog::new(),
            checkpoint_event_count: 0,
            epoch_manager: EpochManager::default(),
        }
    }

    /// Current Merkle root.
    pub fn current_root(&mut self) -> pallas::Base {
        self.tree.root()
    }

    /// Number of note commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.tree.len()
    }

    /// Total shielded balance.
    pub fn pool_balance(&self) -> u64 {
        self.pool_balance
    }

    /// Number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Check whether a nullifier has been spent (constant-time comparison).
    pub fn is_nullifier_spent(&self, nf: pallas::Base) -> bool {
        self.nullifiers.contains(&NullifierEntry(field_to_bytes(nf)))
    }

    /// Check whether a root is in the recent history.
    pub fn is_known_root(&self, root: pallas::Base) -> bool {
        self.root_history.contains(&root)
    }

    /// Insert a commitment into the tree and record the new root in history.
    pub fn insert_commitment(&mut self, commitment: pallas::Base) -> u64 {
        let idx = self.tree.insert(commitment);
        let new_root = self.tree.root();
        self.root_history.push(new_root);
        // Trim to keep only the last ROOT_HISTORY_SIZE roots.
        if self.root_history.len() > ROOT_HISTORY_SIZE {
            let excess = self.root_history.len() - ROOT_HISTORY_SIZE;
            self.root_history.drain(..excess);
        }
        idx
    }

    /// Mark a nullifier as spent. Returns false if already spent.
    /// Also records the nullifier in the current epoch for cross-chain sync.
    pub(crate) fn spend_nullifier(&mut self, nf: pallas::Base) -> bool {
        let inserted = self.nullifiers.insert(NullifierEntry(field_to_bytes(nf)));
        if inserted {
            self.epoch_manager.record_nullifier(nf);
        }
        inserted
    }

    /// Access the epoch manager (e.g. to finalize or query epoch roots).
    pub fn epoch_manager(&self) -> &EpochManager {
        &self.epoch_manager
    }

    /// Mutable access to the epoch manager.
    pub fn epoch_manager_mut(&mut self) -> &mut EpochManager {
        &mut self.epoch_manager
    }

    /// Access the underlying tree (for witness generation).
    pub fn tree(&self) -> &IncrementalMerkleTree {
        &self.tree
    }

    /// Emit a pool event.
    pub fn emit_event(&mut self, event: PoolEvent) {
        self.event_log.emit(event);
    }

    /// Replay an event from a trusted sync delta, applying all state changes
    /// (nullifiers, commitments, pool balance) **without** proof verification.
    ///
    /// Returns the leaf indices for any commitments inserted, or `None` for
    /// deposits (which should use the regular deposit path).
    pub fn replay_transfer_event(
        &mut self,
        nullifiers: &[pallas::Base; 2],
        output_commitments: &[pallas::Base; 2],
    ) -> Result<[u64; 2], ContractError> {
        for nf in nullifiers {
            if !self.spend_nullifier(*nf) {
                return Err(ContractError::NullifierAlreadySpent);
            }
        }
        let mut leaf_indices = [0u64; 2];
        for (i, cm) in output_commitments.iter().enumerate() {
            leaf_indices[i] = self.insert_commitment(*cm);
        }
        Ok(leaf_indices)
    }

    /// Replay a withdraw event from a trusted sync delta.
    ///
    /// Returns `Err(ContractError::InsufficientBalance)` if `amount` exceeds the
    /// pool balance, which would indicate replayed data is inconsistent.
    pub fn replay_withdraw_event(
        &mut self,
        nullifiers: &[pallas::Base; 2],
        change_commitments: &[pallas::Base; 2],
        amount: u64,
    ) -> Result<[u64; 2], ContractError> {
        for nf in nullifiers {
            if !self.spend_nullifier(*nf) {
                return Err(ContractError::NullifierAlreadySpent);
            }
        }
        let mut leaf_indices = [0u64; 2];
        for (i, cm) in change_commitments.iter().enumerate() {
            leaf_indices[i] = self.insert_commitment(*cm);
        }
        self.pool_balance = self
            .pool_balance
            .checked_sub(amount)
            .ok_or(ContractError::InsufficientPoolBalance)?;
        Ok(leaf_indices)
    }

    /// Access the event log.
    pub fn events(&self) -> &[PoolEvent] {
        self.event_log.events()
    }

    /// Return events that have been emitted since the last checkpoint.
    ///
    /// These are the events that would need to be persisted (or replayed)
    /// to bring a checkpoint-era snapshot up to the current in-memory state.
    pub fn pending_events(&self) -> &[PoolEvent] {
        let all = self.event_log.events();
        if self.checkpoint_event_count >= all.len() {
            &[]
        } else {
            &all[self.checkpoint_event_count..]
        }
    }

    /// Mark the current event log position as a checkpoint boundary.
    ///
    /// After calling this, `pending_events()` will return an empty slice
    /// until new events are emitted.
    pub fn mark_checkpoint(&mut self) {
        self.checkpoint_event_count = self.event_log.len();
    }

    /// Number of events pending since last checkpoint.
    pub fn pending_event_count(&self) -> usize {
        self.event_log.len().saturating_sub(self.checkpoint_event_count)
    }

    /// Save pool state to a JSON file with HMAC integrity.
    ///
    /// Uses atomic write (temp file + rename) to prevent corruption on crash.
    /// Appends an HMAC-SHA256 tag so that tampering is detectable on load.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let envelope = StateFileEnvelope {
            version: STATE_FORMAT_VERSION,
            state: self,
        };
        let json = serde_json::to_string(&envelope)
            .map_err(std::io::Error::other)?;

        let key = integrity_key();
        let mut mac = <Hmac<Sha256>>::new_from_slice(&key)
            .expect("HMAC accepts any key size");
        mac.update(json.as_bytes());
        let tag = mac.finalize().into_bytes();

        let mut payload = json.into_bytes();
        payload.extend_from_slice(&tag);

        // Atomic write: write to a temp sibling, then rename.
        let tmp = path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            std::io::Write::write_all(&mut f, &payload)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, &payload)?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Load pool state from a JSON file, verifying HMAC integrity.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let data = std::fs::read(path)?;
        if data.len() < 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "state file too short",
            ));
        }

        let (json_bytes, tag_bytes) = data.split_at(data.len() - 32);

        let key = integrity_key();
        let mut mac = <Hmac<Sha256>>::new_from_slice(&key)
            .expect("HMAC accepts any key size");
        mac.update(json_bytes);
        mac.verify_slice(tag_bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "state file integrity check failed (file may be corrupted or tampered)",
            )
        })?;

        // Try versioned envelope first; fall back to bare state (v0).
        if let Ok(envelope) = serde_json::from_slice::<StateFileEnvelopeOwned>(json_bytes) {
            if envelope.version > STATE_FORMAT_VERSION {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "state file version {} is newer than supported version {}",
                        envelope.version, STATE_FORMAT_VERSION
                    ),
                ));
            }
            Ok(envelope.state)
        } else {
            // Legacy format (no version envelope) — treat as v0.
            serde_json::from_slice(json_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }
}

/// Default key used for state file integrity checks when `LUMORA_HMAC_KEY`
/// is not set.  Only used as a fallback in development/testing — production
/// deployments MUST set `LUMORA_HMAC_KEY` to a high-entropy secret.
const DEFAULT_INTEGRITY_KEY: &[u8] = b"lumora-state-integrity-v1";

/// Environment variable for the HMAC secret used to sign/verify state files.
const HMAC_KEY_ENV: &str = "LUMORA_HMAC_KEY";

/// When set to "true" or "1", the node will refuse to start without
/// an explicit HMAC key rather than falling back to the compiled-in default.
const REQUIRE_HMAC_KEY_ENV: &str = "LUMORA_REQUIRE_HMAC_KEY";

/// Return the HMAC key to use for state file integrity.
///
/// Reads `LUMORA_HMAC_KEY` from the environment at each call.
/// If `LUMORA_REQUIRE_HMAC_KEY` is set, panics when the key is missing
/// (fail-closed for production). Otherwise falls back with a warning.
fn integrity_key() -> Vec<u8> {
    if let Some(key) = std::env::var(HMAC_KEY_ENV)
        .ok()
        .filter(|k| !k.is_empty())
    {
        return key.into_bytes();
    }

    let require = std::env::var(REQUIRE_HMAC_KEY_ENV)
        .ok()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if require {
        panic!(
            "{HMAC_KEY_ENV} is not set and {REQUIRE_HMAC_KEY_ENV}=true — \
             refusing to use weak default key. Set {HMAC_KEY_ENV} to a \
             high-entropy secret."
        );
    }

    eprintln!(
        "WARNING: {HMAC_KEY_ENV} is not set; using weak default HMAC key. \
         Set this variable to a high-entropy secret in production. \
         Set {REQUIRE_HMAC_KEY_ENV}=true to enforce this requirement.",
    );
    DEFAULT_INTEGRITY_KEY.to_vec()
}

/// Current state file format version.
const STATE_FORMAT_VERSION: u32 = 1;

/// Magic header for binary state files: `LMRA` (4 bytes).
const BINARY_MAGIC: &[u8; 4] = b"LMRA";

impl PrivacyPoolState {
    /// Save pool state in compact binary format with HMAC integrity.
    ///
    /// Format: `[4B magic "LMRA"][4B version LE][JSON payload bytes][32B HMAC-SHA256]`
    ///
    /// Unlike `save()` (which produces human-readable JSON + HMAC), the binary
    /// format omits pretty printing and uses a typed magic header so that
    /// loaders can distinguish file formats.
    pub fn save_binary(&self, path: &std::path::Path) -> std::io::Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let envelope = StateFileEnvelope {
            version: STATE_FORMAT_VERSION,
            state: self,
        };
        let json_bytes = serde_json::to_vec(&envelope)
            .map_err(std::io::Error::other)?;

        let mut buf = Vec::with_capacity(4 + 4 + json_bytes.len() + 32);
        buf.extend_from_slice(BINARY_MAGIC);
        buf.extend_from_slice(&STATE_FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&json_bytes);

        let key = integrity_key();
        let mut mac = <Hmac<Sha256>>::new_from_slice(&key)
            .expect("HMAC accepts any key size");
        mac.update(&buf);
        let tag = mac.finalize().into_bytes();
        buf.extend_from_slice(&tag);

        let tmp = path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            std::io::Write::write_all(&mut f, &buf)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, &buf)?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Load pool state from a binary file, verifying HMAC integrity.
    pub fn load_binary(path: &std::path::Path) -> std::io::Result<Self> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let data = std::fs::read(path)?;
        // Minimum: 4 (magic) + 4 (version) + 2 (minimal JSON) + 32 (HMAC) = 42
        if data.len() < 42 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "binary state file too short",
            ));
        }
        if &data[..4] != BINARY_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid binary state file magic header",
            ));
        }

        let (content, tag_bytes) = data.split_at(data.len() - 32);

        let key = integrity_key();
        let mut mac = <Hmac<Sha256>>::new_from_slice(&key)
            .expect("HMAC accepts any key size");
        mac.update(content);
        mac.verify_slice(tag_bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "binary state file integrity check failed",
            )
        })?;

        let version = u32::from_le_bytes(
            content[4..8].try_into()
                .expect("state header guaranteed >= 8 bytes after HMAC check"),
        );
        if version > STATE_FORMAT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "binary state version {} is newer than supported {}",
                    version, STATE_FORMAT_VERSION
                ),
            ));
        }

        let envelope: StateFileEnvelopeOwned = serde_json::from_slice(&content[8..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(envelope.state)
    }
}

/// Versioned envelope for serializing state (borrows state for save).
#[derive(Serialize)]
struct StateFileEnvelope<'a> {
    version: u32,
    state: &'a PrivacyPoolState,
}

/// Versioned envelope for deserializing state (owns state for load).
#[derive(Deserialize)]
struct StateFileEnvelopeOwned {
    version: u32,
    state: PrivacyPoolState,
}

impl Default for PrivacyPoolState {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a field element to a fixed-size byte array for HashSet storage.
fn field_to_bytes(f: pallas::Base) -> [u8; 32] {
    use ff::PrimeField;
    f.to_repr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_track_and_reject() {
        let mut state = PrivacyPoolState::new();
        let nf = pallas::Base::from(123u64);
        assert!(!state.is_nullifier_spent(nf));
        assert!(state.spend_nullifier(nf)); // first time: success
        assert!(state.is_nullifier_spent(nf));
        assert!(!state.spend_nullifier(nf)); // second time: already spent
    }

    #[test]
    fn root_history_bounded() {
        let mut state = PrivacyPoolState::new();
        // Insert ROOT_HISTORY_SIZE + 10 commitments, check the history doesn't grow unboundedly.
        for i in 0..(ROOT_HISTORY_SIZE as u64 + 10) {
            state.insert_commitment(pallas::Base::from(i));
        }
        // History should be at most ROOT_HISTORY_SIZE.
        assert!(state.root_history.len() <= ROOT_HISTORY_SIZE);
    }

    #[test]
    fn state_save_load_roundtrip() {
        let mut state = PrivacyPoolState::new();
        let cm1 = pallas::Base::from(42u64);
        let cm2 = pallas::Base::from(99u64);
        state.insert_commitment(cm1);
        state.insert_commitment(cm2);
        state.pool_balance = 100;
        let nf = pallas::Base::from(123u64);
        state.spend_nullifier(nf);

        let dir = std::env::temp_dir().join("lumora_test_state");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("state.json");

        state.save(&path).expect("save should succeed");
        let mut loaded = PrivacyPoolState::load(&path).expect("load should succeed");

        assert_eq!(loaded.pool_balance(), 100);
        assert_eq!(loaded.commitment_count(), 2);
        assert!(loaded.is_nullifier_spent(nf));
        assert_eq!(loaded.current_root(), state.current_root());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn state_load_detects_tampering() {
        let mut state = PrivacyPoolState::new();
        state.insert_commitment(pallas::Base::from(1u64));
        state.pool_balance = 50;

        let dir = std::env::temp_dir().join("lumora_test_tamper");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("tampered.json");

        state.save(&path).expect("save should succeed");

        // Tamper with the file by flipping a byte in the JSON body.
        let mut data = std::fs::read(&path).expect("read");
        if !data.is_empty() {
            data[0] ^= 0xFF;
        }
        std::fs::write(&path, &data).expect("write tampered");

        let result = PrivacyPoolState::load(&path);
        assert!(result.is_err(), "loading tampered state should fail");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn state_binary_roundtrip() {
        let mut state = PrivacyPoolState::new();
        let cm1 = pallas::Base::from(42u64);
        let cm2 = pallas::Base::from(99u64);
        state.insert_commitment(cm1);
        state.insert_commitment(cm2);
        state.pool_balance = 200;
        let nf = pallas::Base::from(555u64);
        state.spend_nullifier(nf);

        let dir = std::env::temp_dir().join("lumora_test_binary_state");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("state.bin");

        state.save_binary(&path).expect("binary save should succeed");
        let mut loaded = PrivacyPoolState::load_binary(&path).expect("binary load should succeed");

        assert_eq!(loaded.pool_balance(), 200);
        assert_eq!(loaded.commitment_count(), 2);
        assert!(loaded.is_nullifier_spent(nf));
        assert_eq!(loaded.current_root(), state.current_root());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn state_binary_detects_tampering() {
        let state = PrivacyPoolState::new();

        let dir = std::env::temp_dir().join("lumora_test_binary_tamper");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("tampered.bin");

        state.save_binary(&path).expect("save");

        let mut data = std::fs::read(&path).expect("read");
        if data.len() > 8 {
            data[8] ^= 0xFF;
        }
        std::fs::write(&path, &data).expect("write tampered");

        let result = PrivacyPoolState::load_binary(&path);
        assert!(result.is_err(), "loading tampered binary state should fail");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
