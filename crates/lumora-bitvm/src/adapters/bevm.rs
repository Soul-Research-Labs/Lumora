//! BEVM bridge adapter — BTC-native EVM-compatible L2 using Taproot consensus.
//!
//! BEVM is an EVM-compatible Bitcoin L2 that achieves consensus through
//! Taproot-based multisig. This adapter communicates with BEVM's EVM
//! JSON-RPC endpoint and Taproot-specific extensions.

use std::cell::Cell;

use ff::PrimeField;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, RpcTransport};

use super::{field_to_hex, hex_to_field};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the BEVM bridge adapter.
#[derive(Debug, Clone)]
pub struct BevmConfig {
    /// BEVM EVM RPC endpoint.
    pub rpc_url: String,
    /// BEVM chain ID (default: 11501).
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// Taproot bridge contract address (EVM).
    pub taproot_bridge_address: [u8; 20],
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for BevmConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:8547"),
            chain_id: 11501,
            confirmations: 6,
            taproot_bridge_address: [0; 20],
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

/// Taproot deposit event from the BEVM network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaprootDeposit {
    /// Bitcoin Taproot transaction ID.
    pub btc_tx_id: String,
    /// Taproot output index.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Taproot script path used.
    pub script_path: String,
    /// Number of L1 confirmations.
    pub confirmations: u64,
}

/// BEVM consensus status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// Current block height on BEVM.
    pub block_height: u64,
    /// Number of active Taproot signers.
    pub active_signers: u64,
    /// Required signatures for consensus.
    pub threshold: u64,
    /// Latest finalized L1 block height.
    pub l1_finalized_height: u64,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// BEVM bridge adapter.
pub struct BevmBridge<T: RpcTransport = OfflineTransport> {
    config: BevmConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl BevmBridge<OfflineTransport> {
    pub fn new(config: BevmConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> BevmBridge<T> {
    pub fn with_transport(config: BevmConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &BevmConfig {
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

    /// Get Taproot deposits from the BEVM bridge.
    pub fn get_taproot_deposits(&self) -> Result<Vec<TaprootDeposit>, BridgeError> {
        let result = self.rpc_call("bevm_getTaprootDeposits", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse taproot deposits: {e}")))
    }

    /// Get the current BEVM consensus status.
    pub fn get_consensus_status(&self) -> Result<ConsensusStatus, BridgeError> {
        let result = self.rpc_call("bevm_getConsensusStatus", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse consensus status: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for BevmBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("bevm_getTaprootDeposits", serde_json::json!([]))?;        if result.is_null() { return Ok(vec![]); }        let deposits: Vec<RpcDeposit> = serde_json::from_value(result)
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
            "bevm_submitTaprootWithdrawal",
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
            "bevm_commitStateRoot",
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
            "bevm_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("bevm_getRemoteNullifierRoots", serde_json::json!([]))?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        entries
            .into_iter()
            .map(|e| {
                let chain_id = e["chain_id"].as_u64().unwrap_or(0);
                let epoch_id = e["epoch_id"].as_u64().unwrap_or(0);
                let root = hex_to_field(e["root"].as_str().unwrap_or(""))
                    .unwrap_or(pallas::Base::zero());
                Ok(RemoteNullifierEpochRoot { chain_id, epoch_id, root })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = BevmConfig::default();
        assert_eq!(cfg.chain_id, 11501);
        assert_eq!(cfg.taproot_bridge_address, [0; 20]);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = BevmBridge::new(BevmConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = BevmBridge::new(BevmConfig::default());
        assert_eq!(bridge.config().chain_id, 11501);
    }
}
