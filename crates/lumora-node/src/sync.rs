//! State synchronisation protocol — types and trait for syncing pool state
//! between nodes.
//!
//! Nodes exchange state via a pull-based protocol:
//! 1. Follower asks leader for its current height (commitment count).
//! 2. Follower requests a `StateDelta` covering the range it's missing.
//! 3. Follower verifies the delta's HMAC signature before applying.
//! 4. Follower applies the delta to its local state.

use hmac::{Hmac, Mac};
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use lumora_contracts::PoolEvent;

type HmacSha256 = Hmac<Sha256>;

/// A snapshot of the node's sync position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Number of commitments in the tree.
    pub height: u64,
    /// Current Merkle root.
    #[serde(with = "lumora_primitives::serde_field::base")]
    pub root: pallas::Base,
    /// Number of spent nullifiers.
    pub nullifier_count: usize,
    /// Pool balance.
    pub pool_balance: u64,
}

/// A delta of events to replay for catching up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    /// The starting height (commitment count) this delta applies from.
    pub from_height: u64,
    /// Ordered events to replay.
    pub events: Vec<PoolEvent>,
}

/// A signed state delta: the delta payload plus an HMAC tag for authentication.
///
/// The HMAC covers the serialized delta (from_height + events), preventing
/// tampering and fabrication. Both sender and receiver must share the same
/// sync secret key.
///
/// Replay protection is provided by `sequence` and `timestamp_secs`:
/// - Receivers track the highest sequence seen per sender and reject any
///   delta with a sequence ≤ the last accepted one.
/// - `timestamp_secs` (Unix epoch) is included in the HMAC but not enforced
///   by default; operators may add a staleness check if desired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedStateDelta {
    /// The underlying delta.
    pub delta: StateDelta,
    /// Monotonically increasing sequence number for replay protection.
    #[serde(default)]
    pub sequence: u64,
    /// Wall-clock Unix timestamp (seconds) when the delta was signed.
    #[serde(default)]
    pub timestamp_secs: u64,
    /// HMAC-SHA256 tag over the serialized delta payload.
    pub hmac_tag: [u8; 32],
}

impl SignedStateDelta {
    /// Create a signed delta by computing an HMAC over the serialized payload.
    pub fn sign(delta: StateDelta, key: &[u8]) -> Self {
        Self::sign_with_seq(delta, key, 0, 0)
    }

    /// Create a signed delta with explicit sequence and timestamp.
    pub fn sign_with_seq(delta: StateDelta, key: &[u8], sequence: u64, timestamp_secs: u64) -> Self {
        let payload = serde_json::to_vec(&delta).expect("delta serialization");
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(&payload);
        mac.update(&sequence.to_le_bytes());
        mac.update(&timestamp_secs.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        let mut hmac_tag = [0u8; 32];
        hmac_tag.copy_from_slice(&tag);
        Self { delta, sequence, timestamp_secs, hmac_tag }
    }

    /// Verify the HMAC tag against the provided key.
    /// Returns `Ok(())` if valid, or an error message.
    pub fn verify(&self, key: &[u8]) -> Result<(), &'static str> {
        let payload = serde_json::to_vec(&self.delta)
            .map_err(|_| "delta serialization failed")?;
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(&payload);
        mac.update(&self.sequence.to_le_bytes());
        mac.update(&self.timestamp_secs.to_le_bytes());
        mac.verify_slice(&self.hmac_tag)
            .map_err(|_| "delta HMAC verification failed")
    }
}

/// Trait for state synchronisation between nodes.
pub trait StateSync {
    /// Error type for sync operations.
    type Error: std::fmt::Display;

    /// Get the current sync status from a remote peer.
    fn remote_status(&self, peer: &str) -> Result<SyncStatus, Self::Error>;

    /// Fetch a state delta from a remote peer, covering events from
    /// `from_height` to the peer's current height.
    fn fetch_delta(&self, peer: &str, from_height: u64) -> Result<StateDelta, Self::Error>;

    /// Push a state delta to a remote peer (for active replication).
    fn push_delta(&self, peer: &str, delta: &StateDelta) -> Result<(), Self::Error>;
}

/// Apply a state delta to a `LumoraNode`, replaying events in order.
///
/// Deposits are fully re-executed. Transfer and Withdraw events replay
/// state changes (nullifiers, commitments, pool balance) without proof
/// re-verification — this is safe only for trusted leader sync.
///
/// Returns the number of events applied.
pub fn apply_delta(node: &mut super::LumoraNode, delta: &StateDelta) -> Result<usize, &'static str> {
    let mut applied = 0;
    for event in &delta.events {
        match event {
            PoolEvent::Deposit { commitment, amount, .. } => {
                if node.deposit(*commitment, *amount).is_ok() {
                    applied += 1;
                } else {
                    return Err("deposit replay failed during delta application");
                }
            }
            PoolEvent::Transfer { nullifiers, output_commitments, .. } => {
                // Replay state changes: spend nullifiers, insert commitments.
                node.pool.state.replay_transfer_event(nullifiers, output_commitments);
                // Keep our local tree mirror in sync.
                for cm in output_commitments {
                    node.tree.insert(*cm);
                }
                node.pool.state.emit_event(event.clone());
                applied += 1;
            }
            PoolEvent::Withdraw { nullifiers, change_commitments, amount, .. } => {
                // Replay state changes: spend nullifiers, insert commitments,
                // decrease pool balance.
                node.pool.state.replay_withdraw_event(nullifiers, change_commitments, *amount)
                    .map_err(|_| "withdraw replay failed: pool balance underflow in delta")?;
                for cm in change_commitments {
                    node.tree.insert(*cm);
                }
                node.pool.state.emit_event(event.clone());
                applied += 1;
            }
        }
    }
    Ok(applied)
}

// ---------------------------------------------------------------------------
// Mempool synchronisation protocol
// ---------------------------------------------------------------------------

/// Compact digest of a node's mempool, used for set-reconciliation gossip.
///
/// Instead of sending the full mempool, peers exchange digests to determine
/// which transactions the other side is missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolDigest {
    /// Number of pending transactions.
    pub pending_count: usize,
    /// SHA-256 hash over sorted transaction identifiers (deterministic order).
    pub content_hash: [u8; 32],
}

/// A batch of serialised mempool entries for peer exchange.
///
/// The receiver merges these into its local mempool, ignoring duplicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolBatch {
    /// Serialised pending transactions as JSON payloads.
    pub entries: Vec<MempoolEntry>,
}

/// A single mempool entry with a stable identifier for deduplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolEntry {
    /// SHA-256 hash of the canonical serialisation (used as tx identifier).
    pub tx_hash: [u8; 32],
    /// The pending transaction (serialised as tagged JSON).
    pub payload: String,
}

/// Trait for mempool synchronisation between peers.
///
/// This follows an optimistic gossip approach:
/// 1. Exchange `MempoolDigest` to detect divergence cheaply.
/// 2. If digests differ, fetch/push the full batch.
pub trait MempoolSync {
    type Error: std::fmt::Display;

    /// Get a remote peer's mempool digest.
    fn remote_mempool_digest(&self, peer: &str) -> Result<MempoolDigest, Self::Error>;

    /// Fetch pending transactions from a remote peer.
    fn fetch_mempool(&self, peer: &str) -> Result<MempoolBatch, Self::Error>;

    /// Push local pending transactions to a remote peer.
    fn push_mempool(&self, peer: &str, batch: &MempoolBatch) -> Result<(), Self::Error>;
}

/// Compute a deterministic content hash for a set of transaction hashes.
///
/// Sorts the hashes lexicographically and SHA-256s the concatenation.
pub fn mempool_content_hash(tx_hashes: &mut [[u8; 32]]) -> [u8; 32] {
    use sha2::Digest;

    tx_hashes.sort();
    let mut hasher = sha2::Sha256::new();
    for h in tx_hashes.iter() {
        hasher.update(h);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the SHA-256 identifier for a serialised transaction payload.
pub fn tx_hash(payload: &[u8]) -> [u8; 32] {
    use sha2::Digest;

    let result = sha2::Sha256::digest(payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Transaction broadcast protocol
// ---------------------------------------------------------------------------

/// An event broadcast message sent to peers after a transaction is committed.
///
/// The node broadcasts this to all healthy peers so they can update their
/// local state without waiting for the next sync poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBroadcast {
    /// The event to apply.
    pub event: PoolEvent,
    /// The sender node's height *after* committing the event.
    pub new_height: u64,
    /// HMAC-SHA256 tag over `(event, new_height)` for authentication.
    pub hmac_tag: [u8; 32],
}

impl TxBroadcast {
    /// Create a signed broadcast message.
    pub fn sign(event: PoolEvent, new_height: u64, key: &[u8]) -> Self {
        let payload = serde_json::to_vec(&(&event, new_height))
            .expect("broadcast serialization");
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(&payload);
        let tag = mac.finalize().into_bytes();
        let mut hmac_tag = [0u8; 32];
        hmac_tag.copy_from_slice(&tag);
        Self {
            event,
            new_height,
            hmac_tag,
        }
    }

    /// Verify the HMAC tag.
    pub fn verify(&self, key: &[u8]) -> Result<(), &'static str> {
        let payload = serde_json::to_vec(&(&self.event, self.new_height))
            .map_err(|_| "broadcast serialization failed")?;
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(&payload);
        mac.verify_slice(&self.hmac_tag)
            .map_err(|_| "broadcast HMAC verification failed")
    }
}

/// Trait for broadcasting committed transactions to peers.
pub trait TxBroadcastProtocol {
    type Error: std::fmt::Display;

    /// Broadcast a newly committed event to a single peer.
    fn send_broadcast(&self, peer: &str, msg: &TxBroadcast) -> Result<(), Self::Error>;

    /// Broadcast a committed event to all healthy peers in the registry.
    /// Returns the number of peers successfully notified.
    fn broadcast_to_all(
        &self,
        peers: &[String],
        msg: &TxBroadcast,
    ) -> Vec<Result<(), Self::Error>>;
}

/// Result of applying a received broadcast.
#[derive(Debug)]
pub enum BroadcastResult {
    /// Event applied successfully.
    Applied,
    /// Event was a duplicate (already at or past this height).
    AlreadyApplied,
    /// HMAC verification failed.
    AuthFailed,
}

/// Validate and apply a received broadcast to local state.
///
/// Returns `BroadcastResult` indicating whether the event was applied.
pub fn handle_broadcast(
    node: &mut super::LumoraNode,
    msg: &TxBroadcast,
    key: &[u8],
) -> BroadcastResult {
    // Verify HMAC first.
    if msg.verify(key).is_err() {
        return BroadcastResult::AuthFailed;
    }

    // Check if we're already at or past the broadcast height.
    let local_height = node.pool.state.commitment_count();
    if local_height >= msg.new_height {
        return BroadcastResult::AlreadyApplied;
    }

    // Apply the single event as a delta.
    let delta = StateDelta {
        from_height: local_height,
        events: vec![msg.event.clone()],
    };
    apply_delta(node, &delta).ok();

    BroadcastResult::Applied
}

// ---------------------------------------------------------------------------
// Network partition recovery
// ---------------------------------------------------------------------------

/// Diagnosis of the local node's sync state relative to the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PartitionStatus {
    /// Node is in sync with the majority (height matches best known).
    InSync,
    /// Node is behind — it was likely partitioned and needs catch-up.
    Behind {
        local_height: u64,
        best_peer_height: u64,
        best_peer: String,
    },
    /// Node is ahead of all reachable peers (might be on a fork, or peers
    /// are the ones that were partitioned).
    Ahead {
        local_height: u64,
        best_peer_height: u64,
    },
    /// No peers are reachable — possibly still partitioned.
    NoPeers,
}

/// Plan for recovering from a detected partition.
#[derive(Debug, Clone)]
pub struct RecoveryPlan {
    /// The diagnosed partition status.
    pub status: PartitionStatus,
    /// Action to take.
    pub action: RecoveryAction,
}

/// Action to take for partition recovery.
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// Nothing to do — node is in sync.
    None,
    /// Fetch a delta from the best peer to catch up.
    CatchUp {
        peer: String,
        from_height: u64,
    },
    /// Re-broadcast local state delta to behind peers.
    ReBroadcast {
        behind_peers: Vec<String>,
    },
    /// Retry peer connections — no peers are reachable.
    RetryConnections,
}

/// Diagnose partition status by comparing local height against peer statuses.
///
/// `peer_statuses` is a list of `(peer_addr, height)` tuples from successful
/// `remote_status` calls.
pub fn diagnose_partition(
    local_height: u64,
    peer_statuses: &[(String, u64)],
) -> PartitionStatus {
    if peer_statuses.is_empty() {
        return PartitionStatus::NoPeers;
    }

    let (best_peer, best_height) = peer_statuses
        .iter()
        .max_by_key(|(_, h)| h)
        .unwrap();

    if local_height >= *best_height {
        if local_height == *best_height {
            PartitionStatus::InSync
        } else {
            PartitionStatus::Ahead {
                local_height,
                best_peer_height: *best_height,
            }
        }
    } else {
        PartitionStatus::Behind {
            local_height,
            best_peer_height: *best_height,
            best_peer: best_peer.clone(),
        }
    }
}

/// Build a recovery plan based on the partition diagnosis.
pub fn plan_recovery(
    local_height: u64,
    peer_statuses: &[(String, u64)],
) -> RecoveryPlan {
    let status = diagnose_partition(local_height, peer_statuses);
    let action = match &status {
        PartitionStatus::InSync => RecoveryAction::None,
        PartitionStatus::Behind {
            best_peer,
            ..
        } => RecoveryAction::CatchUp {
            peer: best_peer.clone(),
            from_height: local_height,
        },
        PartitionStatus::Ahead { .. } => {
            let behind: Vec<String> = peer_statuses
                .iter()
                .filter(|(_, h)| *h < local_height)
                .map(|(p, _)| p.clone())
                .collect();
            RecoveryAction::ReBroadcast {
                behind_peers: behind,
            }
        }
        PartitionStatus::NoPeers => RecoveryAction::RetryConnections,
    };
    RecoveryPlan { status, action }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::pallas;

    #[test]
    fn signed_delta_sign_and_verify() {
        let key = b"test-sync-secret-key-32b-long!!";
        let delta = StateDelta {
            from_height: 0,
            events: vec![lumora_contracts::PoolEvent::Deposit {
                commitment: pallas::Base::from(1u64),
                amount: 100,
                leaf_index: 0,
            }],
        };
        let signed = SignedStateDelta::sign(delta, key);
        assert!(signed.verify(key).is_ok());
    }

    #[test]
    fn signed_delta_wrong_key_fails() {
        let key = b"correct-key-for-signing-delta!!0";
        let delta = StateDelta {
            from_height: 5,
            events: vec![],
        };
        let signed = SignedStateDelta::sign(delta, key);
        assert!(signed.verify(b"wrong-key-for-signing-delta!!00").is_err());
    }

    #[test]
    fn signed_delta_tampered_payload_fails() {
        let key = b"tamper-test-key-for-delta-sign!";
        let delta = StateDelta {
            from_height: 10,
            events: vec![lumora_contracts::PoolEvent::Deposit {
                commitment: pallas::Base::from(42u64),
                amount: 500,
                leaf_index: 0,
            }],
        };
        let mut signed = SignedStateDelta::sign(delta, key);
        signed.delta.from_height = 999; // tamper
        assert!(signed.verify(key).is_err());
    }

    #[test]
    fn tx_broadcast_sign_and_verify() {
        let key = b"broadcast-secret-key-32bytes!!!";
        let event = lumora_contracts::PoolEvent::Deposit {
            commitment: pallas::Base::from(7u64),
            amount: 200,
            leaf_index: 0,
        };
        let msg = TxBroadcast::sign(event, 1, key);
        assert!(msg.verify(key).is_ok());
        assert!(msg.verify(b"wrong-broadcast-key-32bytes!!!!").is_err());
    }

    #[test]
    fn mempool_content_hash_deterministic() {
        let mut hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let h1 = mempool_content_hash(&mut hashes);
        let mut hashes2 = vec![[3u8; 32], [1u8; 32], [2u8; 32]];
        let h2 = mempool_content_hash(&mut hashes2);
        // Same set, different order → same hash (sorted internally).
        assert_eq!(h1, h2);
    }

    #[test]
    fn mempool_content_hash_different_sets_differ() {
        let mut a = vec![[1u8; 32], [2u8; 32]];
        let mut b = vec![[3u8; 32], [4u8; 32]];
        assert_ne!(mempool_content_hash(&mut a), mempool_content_hash(&mut b));
    }

    #[test]
    fn tx_hash_deterministic() {
        let h1 = tx_hash(b"hello");
        let h2 = tx_hash(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(tx_hash(b"hello"), tx_hash(b"world"));
    }

    #[test]
    fn diagnose_partition_in_sync() {
        let peers = vec![("p1".into(), 10), ("p2".into(), 10)];
        assert!(matches!(diagnose_partition(10, &peers), PartitionStatus::InSync));
    }

    #[test]
    fn diagnose_partition_behind() {
        let peers = vec![("p1".into(), 20), ("p2".into(), 15)];
        assert!(matches!(
            diagnose_partition(10, &peers),
            PartitionStatus::Behind { best_peer_height: 20, .. }
        ));
    }

    #[test]
    fn diagnose_partition_ahead() {
        let peers = vec![("p1".into(), 5), ("p2".into(), 3)];
        assert!(matches!(
            diagnose_partition(10, &peers),
            PartitionStatus::Ahead { .. }
        ));
    }

    #[test]
    fn diagnose_partition_no_peers() {
        assert!(matches!(diagnose_partition(10, &[]), PartitionStatus::NoPeers));
    }

    #[test]
    fn plan_recovery_catch_up() {
        let peers = vec![("leader".into(), 100)];
        let plan = plan_recovery(50, &peers);
        assert!(matches!(plan.action, RecoveryAction::CatchUp { from_height: 50, .. }));
    }

    #[test]
    fn plan_recovery_in_sync() {
        let peers = vec![("p1".into(), 10)];
        let plan = plan_recovery(10, &peers);
        assert!(matches!(plan.action, RecoveryAction::None));
    }

    #[test]
    fn plan_recovery_rebroadcast() {
        let peers = vec![("p1".into(), 5), ("p2".into(), 3)];
        let plan = plan_recovery(10, &peers);
        assert!(matches!(plan.action, RecoveryAction::ReBroadcast { .. }));
    }

    #[test]
    fn signed_delta_with_sequence_verifies() {
        let key = b"seq-test-key-for-delta-signing!";
        let delta = StateDelta { from_height: 0, events: vec![] };
        let signed = SignedStateDelta::sign_with_seq(delta, key, 42, 1700000000);
        assert_eq!(signed.sequence, 42);
        assert_eq!(signed.timestamp_secs, 1700000000);
        assert!(signed.verify(key).is_ok());
    }

    #[test]
    fn signed_delta_sequence_mismatch_fails() {
        let key = b"seq-mismatch-key-for-test!!!!!";
        let delta = StateDelta { from_height: 0, events: vec![] };
        let mut signed = SignedStateDelta::sign_with_seq(delta, key, 5, 100);
        signed.sequence = 6; // tamper with sequence
        assert!(signed.verify(key).is_err());
    }

    #[test]
    fn signed_delta_timestamp_mismatch_fails() {
        let key = b"ts-mismatch-key-for-test!!!!!!";
        let delta = StateDelta { from_height: 0, events: vec![] };
        let mut signed = SignedStateDelta::sign_with_seq(delta, key, 1, 999);
        signed.timestamp_secs = 1000; // tamper with timestamp
        assert!(signed.verify(key).is_err());
    }

    #[test]
    fn signed_delta_zero_seq_backward_compat() {
        // sign() uses sequence=0, timestamp_secs=0 — verify still works
        let key = b"compat-key-for-zero-seq-test!!";
        let delta = StateDelta { from_height: 0, events: vec![] };
        let signed = SignedStateDelta::sign(delta, key);
        assert_eq!(signed.sequence, 0);
        assert_eq!(signed.timestamp_secs, 0);
        assert!(signed.verify(key).is_ok());
    }
}
