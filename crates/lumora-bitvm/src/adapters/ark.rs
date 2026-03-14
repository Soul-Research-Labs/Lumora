//! Ark protocol bridge adapter — Virtual UTXO (vTXO) off-chain scaling.
//!
//! Ark is a second-layer protocol for Bitcoin that uses virtual UTXOs
//! (vTXOs) and an Ark Service Provider (ASP) to batch transactions
//! into round-based settlement. Users can transact off-chain with
//! unilateral exit capability back to layer 1.

use std::cell::Cell;

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, RpcTransport};

use super::{field_to_hex, hex_to_field};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Ark protocol bridge adapter.
#[derive(Debug, Clone)]
pub struct ArkConfig {
    /// ASP (Ark Service Provider) endpoint.
    pub rpc_url: String,
    /// ASP URL for round participation.
    pub asp_url: String,
    /// Round interval in seconds.
    pub round_interval_secs: u64,
    /// vTXO expiry in blocks.
    pub vtxo_expiry_blocks: u64,
    /// Minimum vTXO value in satoshis.
    pub min_vtxo_sats: u64,
}

impl Default for ArkConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:7070"),
            asp_url: String::from("http://127.0.0.1:7070"),
            round_interval_secs: 10,
            vtxo_expiry_blocks: 144,
            min_vtxo_sats: 1_000,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcVtxoDeposit {
    commitment: String,
    amount: u64,
    vtxo_id: String,
    round_txid: String,
}

/// Virtual UTXO (vTXO) information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vtxo {
    /// Virtual UTXO identifier.
    pub vtxo_id: String,
    /// Value in satoshis.
    pub amount_sats: u64,
    /// Round transaction ID that created this vTXO.
    pub round_txid: String,
    /// Expiry block height.
    pub expiry_block: u64,
    /// Whether this vTXO is spent.
    pub spent: bool,
}

/// Ark round information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkRound {
    /// Round identifier.
    pub round_id: u64,
    /// Round transaction ID on Bitcoin L1.
    pub round_txid: String,
    /// Number of vTXOs created in this round.
    pub vtxo_count: u32,
    /// Total value in this round (sats).
    pub total_value_sats: u64,
    /// Whether the round is finalized.
    pub finalized: bool,
}

/// Redemption request info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedemptionRequest {
    /// Request identifier.
    pub request_id: String,
    /// vTXO being redeemed.
    pub vtxo_id: String,
    /// Status: "pending", "included", "settled".
    pub status: String,
    /// Destination Bitcoin address (if L1 exit).
    pub destination: Option<String>,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Ark protocol bridge adapter.
pub struct ArkBridge<T: RpcTransport = OfflineTransport> {
    config: ArkConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl ArkBridge<OfflineTransport> {
    pub fn new(config: ArkConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> ArkBridge<T> {
    pub fn with_transport(config: ArkConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &ArkConfig {
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

    /// Get the current Ark round.
    pub fn get_current_round(&self) -> Result<ArkRound, BridgeError> {
        let result = self.rpc_call("ark_getCurrentRound", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse round: {e}")))
    }

    /// Submit a request to create a vTXO in the next round.
    pub fn submit_vtxo_request(
        &self,
        amount_sats: u64,
        commitment: &str,
    ) -> Result<String, BridgeError> {
        let result = self.rpc_call(
            "ark_submitVtxoRequest",
            serde_json::json!({ "amount": amount_sats, "commitment": commitment }),
        )?;
        result["request_id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| BridgeError::ConnectionError("missing request_id".into()))
    }

    /// Get vTXO status by ID.
    pub fn get_vtxo_status(&self, vtxo_id: &str) -> Result<Vtxo, BridgeError> {
        let result = self.rpc_call(
            "ark_getVtxoStatus",
            serde_json::json!([vtxo_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse vtxo: {e}")))
    }

    /// Refresh a vTXO before expiry (extend its lifetime).
    pub fn refresh_vtxo(&self, vtxo_id: &str) -> Result<Vtxo, BridgeError> {
        let result = self.rpc_call(
            "ark_refreshVtxo",
            serde_json::json!([vtxo_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse vtxo: {e}")))
    }

    /// Initiate unilateral exit to Bitcoin L1.
    pub fn unilateral_exit(&self, vtxo_id: &str) -> Result<String, BridgeError> {
        let result = self.rpc_call(
            "ark_unilateralExit",
            serde_json::json!([vtxo_id]),
        )?;
        result["exit_txid"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| BridgeError::ConnectionError("missing exit_txid".into()))
    }
}

impl<T: RpcTransport> RollupBridge for ArkBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("ark_getVtxoDeposits", serde_json::json!([]))?;
        if result.is_null() { return Ok(vec![]); }
        let deposits: Vec<RpcVtxoDeposit> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse deposits: {e}")))?;
        deposits
            .into_iter()
            .map(|d| {
                let commitment = hex_to_field(&d.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&d.round_txid)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad txid: {e}")))?;
                Ok(InboundDeposit { commitment, amount: d.amount, tx_id })
            })
            .collect()
    }

    fn execute_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "ark_submitRedemption",
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
        let request_id = result["request_id"]
            .as_str()
            .ok_or_else(|| BridgeError::WithdrawFailed("missing request_id".into()))?;
        Ok(request_id.as_bytes().to_vec())
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "ark_commitStateRoot",
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
            "ark_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("ark_getRemoteNullifierRoots", serde_json::json!([]))?;
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
        let cfg = ArkConfig::default();
        assert_eq!(cfg.round_interval_secs, 10);
        assert_eq!(cfg.vtxo_expiry_blocks, 144);
        assert_eq!(cfg.min_vtxo_sats, 1_000);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = ArkBridge::new(ArkConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = ArkBridge::new(ArkConfig::default());
        assert_eq!(bridge.config().round_interval_secs, 10);
    }
}
