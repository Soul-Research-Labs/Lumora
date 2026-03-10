//! LUMORA Circuits — Halo2 ZK circuits for private transactions.
//!
//! The primary circuit is `TransferCircuit`: a 2-input-2-output private transfer
//! that proves value conservation, Merkle membership of inputs, nullifier derivation,
//! and output commitment well-formedness — all without revealing any private values.

pub mod aggregation;
pub mod gadgets;
pub mod recursive;
pub mod transfer;
pub mod variable_io;
pub mod wealth_proof;
pub mod withdraw;

use serde::{Deserialize, Serialize};

/// Circuit version identifier.
///
/// Each version corresponds to a specific circuit layout, constraint set,
/// and public input count. Proofs generated with one version can only be
/// verified with the matching verifying key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CircuitVersion {
    /// Initial release: 2-in-2-out transfer/withdraw, K=13, depth-32 Merkle.
    V1,
}

impl CircuitVersion {
    /// The current (latest) circuit version.
    pub const CURRENT: Self = Self::V1;

    /// Circuit size parameter (k) for this version.
    pub fn k(&self) -> u32 {
        match self {
            Self::V1 => 13,
        }
    }

    /// Number of public inputs for the transfer circuit.
    pub fn transfer_public_inputs(&self) -> usize {
        match self {
            Self::V1 => transfer::NUM_PUBLIC_INPUTS,
        }
    }

    /// Number of public inputs for the withdrawal circuit.
    pub fn withdraw_public_inputs(&self) -> usize {
        match self {
            Self::V1 => withdraw::NUM_WITHDRAW_PUBLIC_INPUTS,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::V1 => "v1-transfer-2in2out-k13",
        }
    }
}

impl std::fmt::Display for CircuitVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Descriptor carrying all metadata about a circuit version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitDescriptor {
    pub version: CircuitVersion,
    pub k: u32,
    pub num_transfer_public_inputs: usize,
    pub num_withdraw_public_inputs: usize,
    pub merkle_depth: usize,
    pub label: String,
}

impl CircuitDescriptor {
    /// Build a descriptor for the given version.
    pub fn for_version(version: CircuitVersion) -> Self {
        Self {
            version,
            k: version.k(),
            num_transfer_public_inputs: version.transfer_public_inputs(),
            num_withdraw_public_inputs: version.withdraw_public_inputs(),
            merkle_depth: 32,
            label: version.label().to_string(),
        }
    }

    /// Descriptor for the current (latest) circuit version.
    pub fn current() -> Self {
        Self::for_version(CircuitVersion::CURRENT)
    }
}
