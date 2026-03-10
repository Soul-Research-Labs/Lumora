//! LUMORA SDK — high-level interface to the privacy coprocessor.
//!
//! This crate orchestrates the node, wallet, and cryptographic layers
//! into a simple API: `Lumora::init()` → `deposit()` → `send()` → `withdraw()`.

pub mod convert;
pub mod lumora;

// ── Re-exports for downstream consumers ──────────────────────────────────────

// Core types
pub use lumora_primitives::{pallas, vesta};
pub use lumora_note::{Note, SpendingKey, ViewingKey, NoteCommitment, Nullifier};
pub use lumora_note::note::AssetId;
pub use lumora_prover::{InputNote, OutputNote, TransferProof, WithdrawProof};
pub use lumora_contracts::{
    ContractError, DepositReceipt, TransferReceipt, WithdrawReceipt,
};
pub use lumora_client::wallet::{Wallet, OwnedNote};
pub use lumora_node::daemon::LumoraNode;
pub use lumora_node::note_store::{EncryptedNote, NoteStore, RecipientTag};

// High-level orchestrator
pub use crate::lumora::Lumora;
