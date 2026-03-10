//! Event log for the privacy pool.
//!
//! Records all state-changing operations for auditing and indexing.
//! Supports optional transparency memos for selective disclosure.

use pasta_curves::pallas;
use serde::{Serialize, Deserialize};

/// Optional plaintext metadata attached to a transaction for selective disclosure.
///
/// When present, this reveals transaction details (sender viewing key, amounts,
/// asset type) to anyone who can read the event log. This is opt-in — the
/// sender chooses to include a memo for regulatory compliance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparencyMemo {
    /// Hex-encoded viewing key of the sender (for auditor identification).
    pub sender_viewing_key_hex: String,
    /// Plaintext amount transferred or withdrawn.
    pub amount: u64,
    /// Asset identifier.
    pub asset: u64,
    /// Free-form compliance tag (e.g., "KYC-verified", "regulated-transfer").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_tag: Option<String>,
}

/// An event emitted by the privacy pool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PoolEvent {
    /// A new deposit was made.
    Deposit {
        #[serde(with = "lumora_primitives::serde_field::base")]
        commitment: pallas::Base,
        amount: u64,
        leaf_index: u64,
    },
    /// A private transfer was executed.
    Transfer {
        #[serde(with = "lumora_primitives::serde_field::base_array")]
        nullifiers: [pallas::Base; 2],
        #[serde(with = "lumora_primitives::serde_field::base_array")]
        output_commitments: [pallas::Base; 2],
        leaf_indices: [u64; 2],
        /// Optional transparency memo for selective disclosure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency_memo: Option<TransparencyMemo>,
        /// Domain chain ID (V2 nullifiers). `None` = V1 nullifiers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_chain_id: Option<u64>,
        /// Domain application ID (V2 nullifiers).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_app_id: Option<u64>,
    },
    /// A withdrawal was executed.
    Withdraw {
        #[serde(with = "lumora_primitives::serde_field::base_array")]
        nullifiers: [pallas::Base; 2],
        #[serde(with = "lumora_primitives::serde_field::base_array")]
        change_commitments: [pallas::Base; 2],
        amount: u64,
        recipient: [u8; 32],
        leaf_indices: [u64; 2],
        /// Optional transparency memo for selective disclosure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transparency_memo: Option<TransparencyMemo>,
        /// Domain chain ID (V2 nullifiers). `None` = V1 nullifiers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_chain_id: Option<u64>,
        /// Domain application ID (V2 nullifiers).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain_app_id: Option<u64>,
    },
}

/// An append-only event log.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventLog {
    events: Vec<PoolEvent>,
}

impl EventLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn emit(&mut self, event: PoolEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[PoolEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
