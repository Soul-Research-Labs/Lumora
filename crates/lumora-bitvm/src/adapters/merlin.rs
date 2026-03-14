//! Merlin Chain bridge adapter — ZK rollup with BTC-native staking.
//!
//! Merlin Chain is a Bitcoin ZK rollup that supports BTC staking as part of
//! its consensus mechanism. This adapter communicates with Merlin's EVM-compatible
//! RPC endpoint and Bitcoin-specific extensions for deposit/withdrawal operations.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Merlin Chain bridge adapter.
#[derive(Debug, Clone)]
pub struct MerlinConfig {
    /// Merlin RPC endpoint (EVM-compatible).
    pub rpc_url: String,
    /// Merlin chain ID (default: 4200).
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// L1 bridge contract address (EVM).
    pub l1_bridge_address: [u8; 20],
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for MerlinConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:8546"),
            chain_id: 4200,
            confirmations: 6,
            l1_bridge_address: [0; 20],
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
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcWithdrawalResult {
    tx_id: String,
}

/// ZK batch information from the Merlin sequencer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkBatchInfo {
    /// Batch index.
    pub batch_index: u64,
    /// ZK proof hash.
    pub proof_hash: String,
    /// State root after the batch.
    pub state_root: String,
    /// Status: "pending", "proving", "verified".
    pub status: String,
    /// Number of L2 transactions in the batch.
    pub l2_tx_count: u64,
}

/// BTC staking deposit information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcStakingDeposit {
    /// Bitcoin UTXO transaction ID.
    pub btc_tx_id: String,
    /// Amount staked in satoshis.
    pub amount_sats: u64,
    /// Staking duration in Bitcoin blocks.
    pub lock_blocks: u64,
    /// Staker's public key (hex).
    pub staker_pubkey: String,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Merlin Chain bridge adapter.
bridge_boilerplate!(MerlinBridge, MerlinConfig);

impl<T: RpcTransport> MerlinBridge<T> {
    /// Get ZK batch info from the sequencer.
    pub fn get_zk_batch_info(&self, batch_index: u64) -> Result<ZkBatchInfo, BridgeError> {
        let result = self.rpc_call(
            "merlin_getZkBatchRoot",
            serde_json::json!([batch_index]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse ZK batch info: {e}")))
    }

    /// Get BTC staking deposits for a given staker public key.
    pub fn get_btc_staking_deposits(
        &self,
        staker_pubkey: &str,
    ) -> Result<Vec<BtcStakingDeposit>, BridgeError> {
        let result = self.rpc_call(
            "merlin_getBtcStakingDeposits",
            serde_json::json!([staker_pubkey]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse staking deposits: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for MerlinBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("merlin_getBtcDeposits", serde_json::json!([]))?;        if result.is_null() { return Ok(vec![]); }        let deposits: Vec<RpcDeposit> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse deposits: {e}")))?;
        deposits
            .into_iter()
            .map(|d| {
                let commitment = hex_to_field(&d.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&d.tx_id)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad tx_id: {e}")))?;
                Ok(InboundDeposit { commitment, amount: d.amount, tx_id })
            })
            .collect()
    }

    fn execute_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "merlin_submitBtcWithdrawal",
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
            "merlin_commitStateRoot",
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
            "merlin_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("merlin_getRemoteNullifierRoots", serde_json::json!([]))?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for MerlinBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "merlin_verifyProof",
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
        let cfg = MerlinConfig::default();
        assert_eq!(cfg.chain_id, 4200);
        assert_eq!(cfg.confirmations, 6);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = MerlinBridge::new(MerlinConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = MerlinBridge::new(MerlinConfig::default());
        assert_eq!(bridge.config().chain_id, 4200);
    }
}
