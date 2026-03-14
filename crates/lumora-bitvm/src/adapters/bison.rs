//! Bison Labs bridge adapter — ZK-STARK rollup with BitVM settlement on Bitcoin.
//!
//! Bison Labs uses ZK-STARK proofs for execution validity and settles
//! via BitVM on Bitcoin L1. The adapter communicates with the Bison
//! sequencer for deposit/withdrawal operations and proof status tracking.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Bison Labs bridge adapter.
#[derive(Debug, Clone)]
pub struct BisonConfig {
    /// Bison sequencer RPC endpoint.
    pub rpc_url: String,
    /// Bison chain ID.
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// STARK proof verification service URL.
    pub stark_proof_url: String,
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for BisonConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:18560"),
            chain_id: 2649,
            confirmations: 6,
            stark_proof_url: String::from("http://127.0.0.1:18561"),
            max_batch_size: 64,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcDeposit {
    commitment: String,
    amount: u64,
    tx_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcWithdrawalResult {
    tx_id: String,
    batch_id: u64,
}

/// STARK proof status for a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProofStatus {
    /// Batch identifier.
    pub batch_id: u64,
    /// Status: "generating", "submitted", "verified", "failed".
    pub status: String,
    /// L1 transaction ID where the proof was posted (if submitted).
    pub l1_tx_id: Option<String>,
    /// Number of transactions in the batch.
    pub tx_count: u64,
}

/// Batch root commitment information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRoot {
    /// Batch identifier.
    pub batch_id: u64,
    /// State root after applying the batch.
    pub state_root: String,
    /// Previous state root.
    pub prev_state_root: String,
    /// L1 block height of commitment.
    pub l1_height: u64,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Bison Labs bridge adapter.
bridge_boilerplate!(BisonBridge, BisonConfig);

impl<T: RpcTransport> BisonBridge<T> {
    pub fn get_stark_proof_status(
        &self,
        batch_id: u64,
    ) -> Result<StarkProofStatus, BridgeError> {
        let result = self.rpc_call(
            "bison_getZkProofStatus",
            serde_json::json!([batch_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse STARK proof status: {e}")))
    }

    /// Get the batch root commitment for a given batch.
    pub fn get_batch_root(&self, batch_id: u64) -> Result<BatchRoot, BridgeError> {
        let result = self.rpc_call(
            "bison_getBatchRoot",
            serde_json::json!([batch_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse batch root: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for BisonBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("bison_getDeposits", serde_json::json!([]))?;
        if result.is_null() { return Ok(vec![]); }
        let deposits: Vec<RpcDeposit> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse deposits: {e}")))?;
        deposits
            .into_iter()
            .map(|d| {
                let commitment = hex_to_field(&d.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&d.tx_id)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad tx_id: {e}")))?;
                Ok(InboundDeposit {
                    commitment,
                    amount: d.amount,
                    tx_id,
                })
            })
            .collect()
    }

    fn execute_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "bison_submitWithdrawal",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
            }),
        )?;
        let wr: RpcWithdrawalResult = serde_json::from_value(result)
            .map_err(|e| BridgeError::WithdrawFailed(format!("parse result: {e}")))?;
        hex::decode(&wr.tx_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid tx_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "bison_commitStateRoot",
            serde_json::json!({ "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: u64,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        self.rpc_call(
            "bison_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("bison_getRemoteNullifierRoots", serde_json::json!([]))?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for BisonBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "bison_verifyProof",
            serde_json::json!({ "proof_hash": proof_hash }),
        )?;
        result
            .as_bool()
            .ok_or_else(|| BridgeError::VerificationFailed("expected boolean result".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = BisonConfig::default();
        assert_eq!(cfg.chain_id, 2649);
        assert_eq!(cfg.max_batch_size, 64);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = BisonBridge::new(BisonConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = BisonBridge::new(BisonConfig::default());
        assert_eq!(bridge.config().chain_id, 2649);
    }
}
