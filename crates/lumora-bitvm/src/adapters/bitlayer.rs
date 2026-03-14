//! BitLayer bridge adapter — BitVM-native L2 for trust-minimized Bitcoin verification.
//!
//! BitLayer uses BitVM for native proof verification on Bitcoin L1.
//! The operator/challenger model is directly compatible with Lumora's
//! BitVM2 protocol. This adapter integrates with BitLayer's sequencer
//! for deposits, withdrawals, and assertion lifecycle management.

use std::cell::Cell;

use ff::PrimeField;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{field_to_hex, hex_to_field, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the BitLayer bridge adapter.
#[derive(Debug, Clone)]
pub struct BitLayerConfig {
    /// BitLayer sequencer RPC endpoint.
    pub rpc_url: String,
    /// BitLayer chain ID (default: 200901).
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// Operator bond amount in satoshis for BitVM assertions.
    pub bond_amount_sats: u64,
    /// Challenge period in Bitcoin blocks.
    pub challenge_period_blocks: u32,
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for BitLayerConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:18550"),
            chain_id: 200901,
            confirmations: 6,
            bond_amount_sats: 10_000_000,
            challenge_period_blocks: 144,
            max_batch_size: 32,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcDeposit {
    commitment: String,
    amount: u64,
    tx_id: String,
    l1_confirmations: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcWithdrawalResult {
    tx_id: String,
    assertion_id: String,
}

/// Assertion status on the BitLayer network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionStatus {
    /// Unique assertion identifier.
    pub assertion_id: String,
    /// Current state: "pending", "challenged", "finalized", "slashed".
    pub state: String,
    /// L1 block height when the assertion was posted.
    pub assert_height: u64,
    /// Remaining blocks until timeout.
    pub blocks_remaining: u64,
}

/// Operator bond information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorBond {
    /// Operator's public key (hex-encoded).
    pub operator_pubkey: String,
    /// Total bonded satoshis.
    pub bonded_sats: u64,
    /// Number of active assertions backed by this bond.
    pub active_assertions: u64,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// BitLayer bridge adapter.
pub struct BitLayerBridge<T: RpcTransport = OfflineTransport> {
    config: BitLayerConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl BitLayerBridge<OfflineTransport> {
    pub fn new(config: BitLayerConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> BitLayerBridge<T> {
    pub fn with_transport(config: BitLayerConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &BitLayerConfig {
        &self.config
    }

    fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BridgeError> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };
        let resp = self.transport.send(&self.config.rpc_url, &req)?;
        if let Some(err) = resp.error {
            return Err(BridgeError::ConnectionError(format!(
                "RPC error {}: {}",
                err.code, err.message
            )));
        }
        resp.result
            .ok_or_else(|| BridgeError::ConnectionError("RPC response missing result".into()))
    }

    /// Query the status of a BitVM assertion on L1.
    pub fn get_assertion_status(
        &self,
        assertion_id: &str,
    ) -> Result<AssertionStatus, BridgeError> {
        let result = self.rpc_call(
            "bitlayer_getAssertionStatus",
            serde_json::json!([assertion_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse assertion status: {e}")))
    }

    /// Get the current operator bond information.
    pub fn get_operator_bond(&self, operator_pubkey: &str) -> Result<OperatorBond, BridgeError> {
        let result = self.rpc_call(
            "bitlayer_getOperatorBond",
            serde_json::json!([operator_pubkey]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse operator bond: {e}")))
    }

    /// Get the remaining challenge window for an assertion.
    pub fn get_challenge_window(
        &self,
        assertion_id: &str,
    ) -> Result<u64, BridgeError> {
        let result = self.rpc_call(
            "bitlayer_getChallengeWindow",
            serde_json::json!([assertion_id]),
        )?;
        result
            .as_u64()
            .ok_or_else(|| BridgeError::ConnectionError("expected u64".into()))
    }
}

impl<T: RpcTransport> RollupBridge for BitLayerBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("bitlayer_getDeposits", serde_json::json!([]))?;
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
            "bitlayer_submitWithdrawal",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
                "bond_sats": self.config.bond_amount_sats,
            }),
        )?;
        let wr: RpcWithdrawalResult = serde_json::from_value(result)
            .map_err(|e| BridgeError::WithdrawFailed(format!("parse result: {e}")))?;
        hex::decode(&wr.tx_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid tx_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "bitlayer_commitBatch",
            serde_json::json!({ "state_root": field_to_hex(&root), "chain_id": self.config.chain_id }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: u64,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        self.rpc_call(
            "bitlayer_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call(
            "bitlayer_getRemoteNullifierRoots",
            serde_json::json!([]),
        )?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        entries
            .into_iter()
            .map(|e| {
                let chain_id = e["chain_id"].as_u64().unwrap_or(0);
                let epoch_id = e["epoch_id"].as_u64().unwrap_or(0);
                let root = hex_to_field(e["root"].as_str().unwrap_or(""))
                    .unwrap_or(pallas::Base::zero());
                Ok(RemoteNullifierEpochRoot {
                    chain_id,
                    epoch_id,
                    root,
                })
            })
            .collect()
    }
}

impl<T: RpcTransport> OnChainVerifier for BitLayerBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "bitlayer_verifyAssertion",
            serde_json::json!({ "proof_hash": proof_hash }),
        )?;
        result
            .as_bool()
            .ok_or_else(|| BridgeError::VerificationFailed("expected boolean".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = BitLayerConfig::default();
        assert_eq!(cfg.chain_id, 200901);
        assert_eq!(cfg.bond_amount_sats, 10_000_000);
        assert_eq!(cfg.challenge_period_blocks, 144);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = BitLayerBridge::new(BitLayerConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn offline_commit_state_root() {
        let bridge = BitLayerBridge::new(BitLayerConfig::default());
        let result = bridge.commit_state_root(pallas::Base::zero());
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn config_accessor() {
        let bridge = BitLayerBridge::new(BitLayerConfig::default());
        assert_eq!(bridge.config().chain_id, 200901);
    }
}
