//! Reusable circuit gadgets — Poseidon hash, range checks, etc.
//!
//! These wrap `halo2_gadgets` primitives into chip configurations
//! used by the transfer circuit.

pub mod poseidon_chip;
pub mod range_check;
