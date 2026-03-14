//! RGB Protocol bridge adapter — Client-side validated smart contracts on Bitcoin.
//!
//! RGB is a smart contract system built on Bitcoin using client-side
//! validation. State transitions are committed to Bitcoin transactions
//! but validated off-chain via consignments. This adapter integrates
//! with RGB nodes for consignment-based deposits and transfers.

use std::cell::Cell;

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, RpcTransport};

use super::{field_to_hex, hex_to_field};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the RGB Protocol bridge adapter.
#[derive(Debug, Clone)]
pub struct RgbConfig {
    /// RGB node RPC endpoint.
    pub rpc_url: String,
    /// Electrum server URL for UTXO lookups.
    pub electrum_url: String,
    /// RGB schema ID for the Lumora contract.
    pub schema_id: String,
    /// Directory for storing consignment files.
    pub consignment_dir: String,
    /// Required Bitcoin confirmations for finality.
    pub confirmations: u64,
}

impl Default for RgbConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:63963"),
            electrum_url: String::from("tcp://127.0.0.1:50001"),
            schema_id: String::new(),
            consignment_dir: String::from("/tmp/lumora-rgb-consignments"),
            confirmations: 3,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcTransfer {
    commitment: String,
    amount: u64,
    consignment_id: String,
    anchor_tx_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcConsignmentResult {
    consignment_id: String,
    anchor_tx_id: String,
}

/// Result of consignment validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsignmentValidation {
    /// Consignment identifier.
    pub consignment_id: String,
    /// Whether the consignment is valid.
    pub valid: bool,
    /// Validation warnings (non-fatal).
    pub warnings: Vec<String>,
    /// Validation errors (fatal).
    pub errors: Vec<String>,
}

/// RGB contract state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractState {
    /// Contract identifier.
    pub contract_id: String,
    /// Schema identifier.
    pub schema_id: String,
    /// Known owned state (outpoints and their state data).
    pub owned_states: Vec<OwnedState>,
    /// Global state values.
    pub global_state: serde_json::Value,
}

/// An owned state item in an RGB contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedState {
    /// Bitcoin outpoint (txid:vout).
    pub outpoint: String,
    /// State data (hex-encoded).
    pub state_data: String,
    /// State type identifier.
    pub state_type: u16,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// RGB Protocol bridge adapter.
pub struct RgbBridge<T: RpcTransport = OfflineTransport> {
    config: RgbConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl RgbBridge<OfflineTransport> {
    pub fn new(config: RgbConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> RgbBridge<T> {
    pub fn with_transport(config: RgbConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &RgbConfig {
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

    /// Validate an RGB consignment.
    pub fn validate_consignment(
        &self,
        consignment_id: &str,
    ) -> Result<ConsignmentValidation, BridgeError> {
        let result = self.rpc_call(
            "rgb_validateTransition",
            serde_json::json!([consignment_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse validation: {e}")))
    }

    /// Get the current state of an RGB contract.
    pub fn get_contract_state(&self, contract_id: &str) -> Result<ContractState, BridgeError> {
        let result = self.rpc_call(
            "rgb_getContractState",
            serde_json::json!([contract_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse contract state: {e}")))
    }

    /// Accept an incoming RGB transfer (consignment).
    pub fn accept_transfer(&self, consignment_id: &str) -> Result<bool, BridgeError> {
        let result = self.rpc_call(
            "rgb_acceptTransfer",
            serde_json::json!([consignment_id]),
        )?;
        result
            .as_bool()
            .ok_or_else(|| BridgeError::ConnectionError("expected boolean".into()))
    }
}

impl<T: RpcTransport> RollupBridge for RgbBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("rgb_getTransfers", serde_json::json!([]))?;
        if result.is_null() { return Ok(vec![]); }
        let transfers: Vec<RpcTransfer> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse transfers: {e}")))?;
        transfers
            .into_iter()
            .map(|t| {
                let commitment = hex_to_field(&t.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&t.anchor_tx_id)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad tx_id: {e}")))?;
                Ok(InboundDeposit { commitment, amount: t.amount, tx_id })
            })
            .collect()
    }

    fn execute_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "rgb_submitConsignment",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
                "schema_id": self.config.schema_id,
            }),
        )?;
        let cr: RpcConsignmentResult = serde_json::from_value(result)
            .map_err(|e| BridgeError::WithdrawFailed(format!("parse result: {e}")))?;
        hex::decode(&cr.anchor_tx_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid anchor tx hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "rgb_commitSchemaRoot",
            serde_json::json!({ "root": field_to_hex(&root), "schema_id": self.config.schema_id }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: u64,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        self.rpc_call(
            "rgb_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("rgb_getRemoteNullifierRoots", serde_json::json!([]))?;
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
        let cfg = RgbConfig::default();
        assert_eq!(cfg.confirmations, 3);
        assert!(!cfg.electrum_url.is_empty());
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = RgbBridge::new(RgbConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = RgbBridge::new(RgbConfig::default());
        assert_eq!(bridge.config().confirmations, 3);
    }
}
