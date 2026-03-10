//! HTTP JSON-RPC server for the Lumora privacy coprocessor.
//!
//! Exposes the core pool operations (deposit, transfer, withdraw) and
//! read-only queries (balance, root, nullifier status) over HTTP.
//!
//! # Running
//!
//! ```sh
//! cargo run -p lumora-rpc
//! ```
//!
//! The server listens on `127.0.0.1:3030` by default.

pub mod server;
pub mod handlers;
pub mod jitter;
pub mod mempool_handlers;
pub mod sync_handlers;
pub mod tasks;
pub mod types;

#[doc(hidden)]
pub use server::test_router;

#[cfg(test)]
mod rpc_tests;
