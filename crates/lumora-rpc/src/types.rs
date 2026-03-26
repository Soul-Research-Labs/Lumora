//! Request and response types for the RPC API.

use serde::{Deserialize, Serialize};

// ── Deposit ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositReq {
    /// Hex-encoded note commitment (32-byte field element).
    pub commitment: String,
    /// Amount to deposit (in base units).
    pub amount: u64,
    /// Asset identifier (0 = native token). Defaults to 0.
    #[serde(default)]
    pub asset: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositResp {
    pub leaf_index: u64,
    pub new_root: String,
}

// ── Transfer ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferReq {
    /// Hex-encoded proof bytes.
    pub proof: String,
    /// Hex-encoded Merkle root.
    pub merkle_root: String,
    /// Hex-encoded nullifiers (exactly 2).
    pub nullifiers: [String; 2],
    /// Hex-encoded output commitments (exactly 2).
    pub output_commitments: [String; 2],
    /// Optional domain chain ID for V2 domain-separated nullifiers.
    #[serde(default)]
    pub domain_chain_id: Option<u64>,
    /// Optional domain application ID for V2 domain-separated nullifiers.
    #[serde(default)]
    pub domain_app_id: Option<u64>,
    /// Fee the sender consents to pay (in base units). Defaults to 0.
    #[serde(default)]
    pub fee: u64,
}

#[derive(Debug, Serialize)]
pub struct TransferResp {
    pub leaf_indices: [u64; 2],
    pub new_root: String,
}

// ── Withdraw ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WithdrawReq {
    /// Hex-encoded proof bytes.
    pub proof: String,
    /// Hex-encoded Merkle root.
    pub merkle_root: String,
    /// Hex-encoded nullifiers (exactly 2).
    pub nullifiers: [String; 2],
    /// Hex-encoded output commitments (exactly 2).
    pub output_commitments: [String; 2],
    /// Amount to withdraw.
    pub amount: u64,
    /// Hex-encoded 32-byte recipient address.
    pub recipient: String,
    /// Asset identifier (0 = native token). Defaults to 0.
    #[serde(default)]
    pub asset: u64,
    /// Optional domain chain ID for V2 domain-separated nullifiers.
    #[serde(default)]
    pub domain_chain_id: Option<u64>,
    /// Optional domain application ID for V2 domain-separated nullifiers.
    #[serde(default)]
    pub domain_app_id: Option<u64>,
    /// Fee the sender consents to pay (in base units). Defaults to 0.
    #[serde(default)]
    pub fee: u64,
}

#[derive(Debug, Serialize)]
pub struct WithdrawResp {
    pub change_leaf_indices: [u64; 2],
    pub new_root: String,
    pub amount: u64,
}

// ── Queries ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResp {
    pub pool_balance: u64,
    pub commitment_count: u64,
    pub merkle_root: String,
    /// Circuit version label.
    pub circuit_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NullifierReq {
    /// Hex-encoded nullifier to check.
    pub nullifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NullifierResp {
    pub spent: bool,
}

// ── Note Store ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct GetNotesReq {
    /// Hex-encoded 32-byte recipient tag.
    pub recipient_tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedNoteResp {
    pub leaf_index: u64,
    pub commitment: String,
    pub ciphertext: String,
    pub ephemeral_pubkey: String,
}

// ── Relay Note ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayNoteReq {
    /// Hex-encoded 32-byte recipient tag.
    pub recipient_tag: String,
    pub leaf_index: u64,
    /// Hex-encoded commitment bytes.
    pub commitment: String,
    /// Hex-encoded ciphertext.
    pub ciphertext: String,
    /// Hex-encoded ephemeral public key.
    pub ephemeral_pubkey: String,
}

// ── Fee Estimation ─────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct FeeEstimateResp {
    /// Estimated fee for a private transfer (in base units).
    pub transfer_fee: u64,
    /// Estimated fee for a withdrawal (in base units).
    pub withdraw_fee: u64,
    /// Minimum deposit amount.
    pub min_deposit: u64,
    /// Minimum withdrawal amount.
    pub min_withdraw: u64,
}

// ── Transaction History ────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryReq {
    /// Start index (0-based) into the event log. Defaults to 0.
    #[serde(default)]
    pub offset: u64,
    /// Maximum number of events to return. Defaults to 100.
    #[serde(default = "default_limit")]
    pub limit: u64,
}

fn default_limit() -> u64 { 100 }

#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryResp {
    /// Total number of events in the log.
    pub total: u64,
    /// Events returned in this page.
    pub events: Vec<serde_json::Value>,
}

// ── Batch Verification ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerifyItem {
    pub proof: String,
    pub merkle_root: String,
    pub nullifiers: [String; 2],
    pub output_commitments: [String; 2],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyReq {
    pub proofs: Vec<BatchVerifyItem>,
}

#[derive(Debug, Serialize)]
pub struct BatchVerifyResp {
    /// `true` if every proof in the batch is valid.
    pub all_valid: bool,
    /// Number of proofs verified.
    pub count: usize,
}

// ── Epoch Roots ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct EpochRootEntry {
    pub epoch_id: u64,
    pub root: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EpochRootsResp {
    pub current_epoch: u64,
    pub roots: Vec<EpochRootEntry>,
}

// ── Stealth Scan ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct StealthScanReq {
    /// Minimum leaf index to start scanning from (inclusive).
    #[serde(default)]
    pub from_leaf_index: u64,
    /// Maximum number of notes to return (default: 1000).
    #[serde(default = "default_scan_limit")]
    pub limit: usize,
}

fn default_scan_limit() -> usize {
    1000
}

/// Maximum number of notes the stealth-scan endpoint will return in a single
/// request, regardless of the `limit` field in the request.
pub const MAX_SCAN_LIMIT: usize = 10_000;

#[derive(Debug, Serialize, Deserialize)]
pub struct StealthScanResp {
    /// All encrypted notes since `from_leaf_index`, for client-side scanning.
    pub notes: Vec<EncryptedNoteResp>,
    /// Total notes returned.
    pub count: usize,
}

// ── Error response ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ErrorResp {
    pub error: String,
}

// ── BitVM Bridge ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BitvmStatusResp {
    /// Whether a BitVM bridge is configured.
    pub bridge_active: bool,
    /// Number of L1 deposits polled and processed.
    pub deposits_processed: u64,
    /// Number of roots committed to the host chain.
    pub roots_committed: u64,
}

#[derive(Debug, Serialize)]
pub struct BitvmPollResp {
    /// Number of new deposits processed in this poll.
    pub new_deposits: usize,
}

#[derive(Debug, Serialize)]
pub struct BitvmCommitRootResp {
    /// Hex-encoded Merkle root that was committed.
    pub committed_root: String,
}
