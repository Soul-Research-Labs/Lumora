//! # lumora-bitvm
//!
//! BitVM2 bridge verifier for Lumora. Enables trustless verification of
//! Halo2 IPA proofs on Bitcoin L1 via an optimistic challenge-response
//! protocol.
//!
//! ## Architecture
//!
//! Rather than encoding the full IPA verifier in Bitcoin Script (impractical),
//! this crate uses a **split-and-hash** strategy:
//!
//! 1. The **operator** runs full IPA verification off-chain, producing an
//!    execution trace with intermediate SHA-256 commitments at each step.
//! 2. The operator publishes the trace Merkle root on Bitcoin via an
//!    **assert transaction**.
//! 3. Any **challenger** can dispute a specific step by posting a
//!    **challenge transaction**.
//! 4. The operator must reveal the step witness; a Taproot leaf script
//!    verifies correctness. If the operator was dishonest, the challenger
//!    claims the operator's bond.
//!
//! ## Modules
//!
//! - [`trace`] — Verification trace model and generation
//! - [`script`] — Bitcoin Script fragments for step verification
//! - [`protocol`] — BitVM2 bisection/challenge protocol
//! - [`transactions`] — Pre-signed Taproot transaction graph
//! - [`bridge`] — `BitvmBridge` implementing `RollupBridge`
//! - [`verifier`] — `BitvmVerifier` implementing `OnChainVerifier`
//! - [`operator`] — Operator daemon logic
//! - [`challenger`] — Challenger monitoring and response
//! - [`config`] — Configuration types

pub mod config;
pub mod trace;
pub mod script;
pub mod protocol;
pub mod transactions;
pub mod keys;
pub mod bridge;
pub mod verifier;
pub mod operator;
pub mod challenger;
