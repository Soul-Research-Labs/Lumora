//! Async proof generation — non-blocking wrappers for Halo2 proof creation.
//!
//! Proof generation is CPU-intensive (3–7 seconds). These wrappers use
//! `tokio::task::spawn_blocking` to offload proving to the Tokio blocking
//! thread pool, keeping the async runtime responsive for other requests.
//!
//! # Example
//!
//! ```ignore
//! let handle = SharedProverHandle::new(prover_params);
//! let proof = async_prove_transfer(handle, inputs, outputs, tree).await?;
//! ```

use halo2_proofs::plonk;

use crate::{
    InputNote, OutputNote, TransferProof, WithdrawProof,
    SharedProverHandle, SharedWithdrawProverHandle,
};
use lumora_tree::IncrementalMerkleTree;

/// Error type for async proof operations.
#[derive(Debug)]
pub enum AsyncProveError {
    /// The Halo2 prover returned an error.
    ProverError(plonk::Error),
    /// The blocking task was cancelled (runtime shutting down).
    TaskCancelled,
}

impl std::fmt::Display for AsyncProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProverError(e) => write!(f, "prover error: {e:?}"),
            Self::TaskCancelled => write!(f, "proof task was cancelled"),
        }
    }
}

impl std::error::Error for AsyncProveError {}

impl From<plonk::Error> for AsyncProveError {
    fn from(e: plonk::Error) -> Self {
        Self::ProverError(e)
    }
}

/// Generate a transfer proof asynchronously.
///
/// Moves all inputs into a `spawn_blocking` task so the calling async
/// context is not blocked during the ~3–6 second proving time.
pub async fn async_prove_transfer(
    handle: SharedProverHandle,
    inputs: [InputNote; 2],
    outputs: [OutputNote; 2],
    mut tree: IncrementalMerkleTree,
    fee: u64,
) -> Result<TransferProof, AsyncProveError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::prove_transfer(&handle, &inputs, &outputs, &mut tree, fee)
    })
    .await
    .map_err(|_| AsyncProveError::TaskCancelled)?;

    result.map_err(AsyncProveError::ProverError)
}

/// Generate a withdrawal proof asynchronously.
pub async fn async_prove_withdraw(
    handle: SharedWithdrawProverHandle,
    inputs: [InputNote; 2],
    outputs: [OutputNote; 2],
    mut tree: IncrementalMerkleTree,
    exit_value: u64,
    fee: u64,
) -> Result<WithdrawProof, AsyncProveError> {
    let result = tokio::task::spawn_blocking(move || {
        crate::prove_withdraw(&handle, &inputs, &outputs, &mut tree, exit_value, fee)
    })
    .await
    .map_err(|_| AsyncProveError::TaskCancelled)?;

    result.map_err(AsyncProveError::ProverError)
}

/// Generate multiple transfer proofs asynchronously using rayon internally.
pub async fn async_prove_transfers_batch(
    handle: SharedProverHandle,
    jobs: Vec<crate::TransferJob>,
) -> Result<Vec<Result<TransferProof, plonk::Error>>, AsyncProveError> {
    tokio::task::spawn_blocking(move || {
        crate::prove_transfers_parallel(&handle, jobs)
    })
    .await
    .map_err(|_| AsyncProveError::TaskCancelled)
}

/// Generate multiple withdrawal proofs asynchronously using rayon internally.
pub async fn async_prove_withdrawals_batch(
    handle: SharedWithdrawProverHandle,
    jobs: Vec<crate::WithdrawJob>,
) -> Result<Vec<Result<WithdrawProof, plonk::Error>>, AsyncProveError> {
    tokio::task::spawn_blocking(move || {
        crate::prove_withdrawals_parallel(&handle, jobs)
    })
    .await
    .map_err(|_| AsyncProveError::TaskCancelled)
}

/// Async-compatible handle that bundles both transfer and withdrawal provers.
#[derive(Clone)]
pub struct AsyncProverBundle {
    pub transfer: SharedProverHandle,
    pub withdraw: SharedWithdrawProverHandle,
}

impl AsyncProverBundle {
    pub fn new(transfer: SharedProverHandle, withdraw: SharedWithdrawProverHandle) -> Self {
        Self { transfer, withdraw }
    }

    /// Prove a transfer asynchronously.
    pub async fn prove_transfer(
        &self,
        inputs: [InputNote; 2],
        outputs: [OutputNote; 2],
        tree: IncrementalMerkleTree,
        fee: u64,
    ) -> Result<TransferProof, AsyncProveError> {
        async_prove_transfer(self.transfer.clone(), inputs, outputs, tree, fee).await
    }

    /// Prove a withdrawal asynchronously.
    pub async fn prove_withdraw(
        &self,
        inputs: [InputNote; 2],
        outputs: [OutputNote; 2],
        tree: IncrementalMerkleTree,
        exit_value: u64,
        fee: u64,
    ) -> Result<WithdrawProof, AsyncProveError> {
        async_prove_withdraw(self.withdraw.clone(), inputs, outputs, tree, exit_value, fee).await
    }
}
