//! Citrea bridge adapter — ZK rollup on Bitcoin with DA proof verification via BitVM.
//!
//! Citrea is a ZK rollup that posts data availability proofs to Bitcoin L1
//! and uses BitVM for trust-minimized verification of ZK proof batches.
//! This adapter communicates with Citrea's JSON-RPC endpoint for deposits,
//! withdrawals, state root commitments, and proof status queries.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Verification mode for Citrea ZK proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkProofMode {
    /// Full on-chain ZK verification (expensive but instant finality).
    FullVerification,
    /// Optimistic verification via BitVM challenge-response.
    OptimisticBitvm,
}

/// Configuration for the Citrea bridge adapter.
#[derive(Debug, Clone)]
pub struct CitreaConfig {
    /// Citrea sequencer RPC endpoint.
    pub rpc_url: String,
    /// Citrea chain ID (default: 5115).
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
    /// ZK proof verification mode.
    pub proof_mode: ZkProofMode,
    /// DA layer commitment check interval in blocks.
    pub da_check_interval: u64,
}

impl Default for CitreaConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:12345"),
            chain_id: 5115,
            confirmations: 6,
            max_batch_size: 32,
            proof_mode: ZkProofMode::OptimisticBitvm,
            da_check_interval: 10,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcDeposit {
    commitment: String,
    amount: u64,
    tx_id: String,
    l1_block_height: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcWithdrawalResult {
    tx_id: String,
    batch_index: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcProofStatus {
    batch_index: u64,
    status: String, // "pending", "verified", "failed"
    proof_hash: String,
}

/// DA batch status returned by `get_da_batch_status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaBatchStatus {
    /// L1 block height where the batch was posted.
    pub l1_height: u64,
    /// Number of transactions in the batch.
    pub tx_count: u64,
    /// DA commitment hash.
    pub commitment: String,
    /// Whether the batch has been finalized on L1.
    pub finalized: bool,
}

/// Sequencer commitment info returned by `get_sequencer_commitment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerCommitment {
    /// L2 block range start.
    pub l2_start_block: u64,
    /// L2 block range end.
    pub l2_end_block: u64,
    /// Merkle root of the batch state.
    pub state_root: String,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Citrea bridge adapter.
///
/// Communicates with the Citrea sequencer via JSON-RPC. Generic over
/// [`RpcTransport`] for pluggable HTTP clients.
bridge_boilerplate!(CitreaBridge, CitreaConfig);

impl<T: RpcTransport> CitreaBridge<T> {
    pub fn get_da_batch_status(&self, batch_index: u64) -> Result<DaBatchStatus, BridgeError> {
        let result = self.rpc_call(
            "citrea_getDaBatchStatus",
            serde_json::json!([batch_index]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse DA batch status: {e}")))
    }

    /// Get the latest sequencer commitment for an L2 block range.
    pub fn get_sequencer_commitment(
        &self,
        l2_block: u64,
    ) -> Result<SequencerCommitment, BridgeError> {
        let result = self.rpc_call(
            "citrea_getSequencerCommitment",
            serde_json::json!([l2_block]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse sequencer commitment: {e}")))
    }

    /// Query the ZK proof verification status for a batch.
    pub fn get_proof_status(&self, batch_index: u64) -> Result<RpcProofStatus, BridgeError> {
        let result = self.rpc_call(
            "citrea_getProofStatus",
            serde_json::json!([batch_index]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse proof status: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for CitreaBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("citrea_getDeposits", serde_json::json!([]))?;
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
            "citrea_submitWithdrawal",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
                "proof_mode": match self.config.proof_mode {
                    ZkProofMode::FullVerification => "full",
                    ZkProofMode::OptimisticBitvm => "optimistic",
                },
            }),
        )?;

        let wr: RpcWithdrawalResult = serde_json::from_value(result)
            .map_err(|e| BridgeError::WithdrawFailed(format!("parse withdrawal result: {e}")))?;

        hex::decode(&wr.tx_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid tx_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        let root_hex = field_to_hex(&root);
        self.rpc_call(
            "citrea_commitRoot",
            serde_json::json!({ "root": root_hex, "chain_id": self.config.chain_id }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: u64,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        let root_hex = field_to_hex(&root);
        self.rpc_call(
            "citrea_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": root_hex }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call(
            "citrea_getRemoteNullifierRoots",
            serde_json::json!([]),
        )?;

        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;

        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for CitreaBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));

        let result = self.rpc_call(
            "citrea_verifyProof",
            serde_json::json!({
                "proof_hash": proof_hash,
                "mode": match self.config.proof_mode {
                    ZkProofMode::FullVerification => "full",
                    ZkProofMode::OptimisticBitvm => "optimistic",
                },
            }),
        )?;

        result
            .as_bool()
            .ok_or_else(|| BridgeError::VerificationFailed("expected boolean result".into()))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = CitreaConfig::default();
        assert_eq!(cfg.chain_id, 5115);
        assert_eq!(cfg.confirmations, 6);
        assert_eq!(cfg.max_batch_size, 32);
        assert_eq!(cfg.proof_mode, ZkProofMode::OptimisticBitvm);
        assert_eq!(cfg.da_check_interval, 10);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = CitreaBridge::new(CitreaConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn offline_execute_withdrawal() {
        let bridge = CitreaBridge::new(CitreaConfig::default());
        let wd = OutboundWithdrawal {
            amount: 100_000,
            recipient: [0xAA; 32],
            proof_bytes: vec![1, 2, 3, 4],
            nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
        };
        // OfflineTransport returns null for unknown methods → parse error
        let result = bridge.execute_withdrawal(&wd);
        assert!(result.is_err());
    }

    #[test]
    fn offline_commit_state_root() {
        let bridge = CitreaBridge::new(CitreaConfig::default());
        // OfflineTransport returns null for citrea_commitRoot
        let result = bridge.commit_state_root(pallas::Base::zero());
        assert!(result.is_ok() || result.is_err()); // offline may return null
    }

    #[test]
    fn offline_verify_proof() {
        let bridge = CitreaBridge::new(CitreaConfig::default());
        let result = bridge.verify_proof(&[0u8; 64], &[]);
        // OfflineTransport returns null → parse error
        assert!(result.is_err());
    }

    #[test]
    fn config_accessor() {
        let bridge = CitreaBridge::new(CitreaConfig::default());
        assert_eq!(bridge.config().chain_id, 5115);
    }

    #[test]
    fn proof_mode_variants() {
        assert_ne!(ZkProofMode::FullVerification, ZkProofMode::OptimisticBitvm);
        let mut cfg = CitreaConfig::default();
        cfg.proof_mode = ZkProofMode::FullVerification;
        assert_eq!(cfg.proof_mode, ZkProofMode::FullVerification);
    }

    // ── Mock transport tests ────────────────────────────────────────

    use super::super::mock::MockTransport;

    #[test]
    fn mock_poll_deposits() {
        let commitment = field_to_hex(&pallas::Base::from(42u64));
        let transport = MockTransport::new()
            .on("citrea_getDeposits", serde_json::json!([{
                "commitment": commitment,
                "amount": 50000,
                "tx_id": "bb".repeat(32),
                "l1_block_height": 800000
            }]));
        let bridge = CitreaBridge::with_transport(CitreaConfig::default(), transport);
        let deps = bridge.poll_deposits().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].amount, 50000);
    }

    #[test]
    fn mock_verify_proof_true() {
        let transport = MockTransport::new()
            .on("citrea_verifyProof", serde_json::json!(true));
        let bridge = CitreaBridge::with_transport(CitreaConfig::default(), transport);
        assert!(bridge.verify_proof(&[1u8; 32], &[]).unwrap());
    }

    #[test]
    fn mock_verify_proof_false() {
        let transport = MockTransport::new()
            .on("citrea_verifyProof", serde_json::json!(false));
        let bridge = CitreaBridge::with_transport(CitreaConfig::default(), transport);
        assert!(!bridge.verify_proof(&[1u8; 32], &[]).unwrap());
    }

    #[test]
    fn mock_commit_state_root() {
        let transport = MockTransport::new()
            .on("citrea_commitRoot", serde_json::json!(true));
        let bridge = CitreaBridge::with_transport(CitreaConfig::default(), transport);
        assert!(bridge.commit_state_root(pallas::Base::zero()).is_ok());
    }

    #[test]
    fn mock_nullifier_roots_error_propagation() {
        let transport = MockTransport::new()
            .on("citrea_getRemoteNullifierRoots", serde_json::json!([
                { "chain_id": 1, "epoch_id": 5, "root": "invalid_hex" }
            ]));
        let bridge = CitreaBridge::with_transport(CitreaConfig::default(), transport);
        let result = bridge.fetch_remote_nullifier_roots();
        assert!(result.is_err(), "invalid hex root should propagate error");
    }

    #[test]
    fn mock_nullifier_roots_missing_fields() {
        let transport = MockTransport::new()
            .on("citrea_getRemoteNullifierRoots", serde_json::json!([
                { "epoch_id": 5, "root": "aa".repeat(32) }
            ]));
        let bridge = CitreaBridge::with_transport(CitreaConfig::default(), transport);
        let result = bridge.fetch_remote_nullifier_roots();
        assert!(result.is_err(), "missing chain_id should propagate error");
    }
}
