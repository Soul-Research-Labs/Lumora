//! LUMORA Client — wallet and transaction builder.
//!
//! Provides a high-level wallet abstraction that:
//! - Manages spending keys and viewing keys
//! - Tracks owned notes (decrypted from the note store)
//! - Builds deposit, transfer, and withdrawal transactions
//! - Computes balances across owned notes

pub mod wallet;
pub mod wallet_manager;

pub use wallet::Wallet;
