//! Error types for the Lumora privacy pool contract.

use core::fmt;

/// Errors that can occur during contract execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// A nullifier has already been spent (double-spend attempt).
    NullifierAlreadySpent,
    /// The proof failed verification.
    InvalidProof,
    /// The Merkle root provided does not match any known root.
    UnknownMerkleRoot,
    /// The deposit amount is zero.
    ZeroDeposit,
    /// The withdrawal amount exceeds pool balance.
    InsufficientPoolBalance,
    /// The withdrawal amount is zero.
    ZeroWithdrawal,
    /// Value conservation violated (inputs != outputs).
    ValueMismatch,
    /// The Merkle tree is full.
    TreeFull,
    /// Deposit would overflow the pool balance.
    PoolBalanceOverflow,
    /// Amount is below the minimum threshold.
    BelowMinimum { minimum: u64, actual: u64 },
    /// Proof generation / verification failed with details.
    ProofError(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullifierAlreadySpent => write!(f, "nullifier already spent"),
            Self::InvalidProof => write!(f, "proof verification failed"),
            Self::UnknownMerkleRoot => write!(f, "unknown merkle root"),
            Self::ZeroDeposit => write!(f, "deposit amount must be non-zero"),
            Self::InsufficientPoolBalance => write!(f, "insufficient pool balance"),
            Self::ZeroWithdrawal => write!(f, "withdrawal amount must be non-zero"),
            Self::ValueMismatch => write!(f, "value conservation violated"),
            Self::TreeFull => write!(f, "merkle tree is full"),
            Self::PoolBalanceOverflow => write!(f, "deposit would overflow pool balance"),
            Self::BelowMinimum { minimum, actual } => write!(f, "amount {actual} below minimum {minimum}"),
            Self::ProofError(detail) => write!(f, "proof error: {detail}"),
        }
    }
}

impl std::error::Error for ContractError {}

impl From<BridgeError> for ContractError {
    fn from(e: BridgeError) -> Self {
        Self::ProofError(e.to_string())
    }
}

impl From<halo2_proofs::plonk::Error> for ContractError {
    fn from(e: halo2_proofs::plonk::Error) -> Self {
        Self::ProofError(format!("{e:?}"))
    }
}

use crate::bridge::BridgeError;
