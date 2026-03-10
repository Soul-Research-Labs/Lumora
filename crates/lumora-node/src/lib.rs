//! LUMORA Node — prover daemon and transaction processor.
//!
//! The node manages the privacy pool state, processes deposit/transfer/withdraw
//! requests, and generates ZK proofs. It maintains a local Merkle tree and
//! encrypted note store for relaying notes to recipients.
//!
//! # Architecture
//!
//! ```text
//! Client → Node API → [proof generation + state update] → receipts
//! ```
//!
//! The node holds:
//! - **PrivacyPool**: on-chain state (Merkle tree, nullifier set, pool balance)
//! - **Prover params**: proving keys for transfer and withdrawal circuits
//! - **Note store**: encrypted notes indexed by recipient viewing key hash

pub mod batch_accumulator;
pub mod note_store;
pub mod daemon;
pub mod mempool;
pub mod peers;
pub mod sync;

pub use batch_accumulator::{BatchAccumulator, BatchConfig};
pub use daemon::LumoraNode;
pub use note_store::NoteStore;
pub use mempool::Mempool;
pub use peers::PeerRegistry;
