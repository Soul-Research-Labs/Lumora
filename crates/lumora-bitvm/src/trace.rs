//! IPA verification trace model and generation.
//!
//! Decomposes Halo2 IPA verification into discrete steps, each producing
//! a SHA-256 commitment over its intermediate state. The full trace is
//! committed via a Merkle tree; only a disputed step needs on-chain
//! verification in Bitcoin Script.
