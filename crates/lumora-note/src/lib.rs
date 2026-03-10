//! LUMORA Note — the UTXO-style private note model.
//!
//! A Note represents a hidden balance owned by a spending key.
//! Notes are never stored directly on-chain; instead, Pedersen commitments
//! are stored in a Merkle tree, and nullifiers are published when spent.
//!
//! # Data flow
//!
//! ```text
//! Note { value, asset, randomness, owner_pub }
//!       ↓
//! Commitment = PedersenCommit(value, randomness)  (stored in Merkle tree)
//!       ↓
//! Nullifier = PoseidonHash(spending_key, commitment)  (published on spend)
//! ```

pub mod commitment;
pub mod encryption;
pub mod keys;
pub mod note;
pub mod nullifier;

pub use commitment::NoteCommitment;
pub use keys::{SpendingKey, StealthMeta, ViewingKey, recipient_tag, stealth_send};
pub use note::Note;
pub use nullifier::Nullifier;
pub use nullifier::NullifierDomain;
