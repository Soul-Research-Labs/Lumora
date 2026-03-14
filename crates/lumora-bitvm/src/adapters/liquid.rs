//! Liquid Network bridge adapter — Federated Bitcoin sidechain.
//!
//! Liquid is a federated sidechain built on the Elements platform.
//! It supports confidential transactions, fast block times (1 min),
//! and peg-in/peg-out with the Bitcoin mainchain via a federation
//! of functionaries (watchmen). This adapter integrates with Liquid
//! nodes for deposit/withdrawal operations.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Liquid Network bridge adapter.
#[derive(Debug, Clone)]
pub struct LiquidConfig {
    /// Elements-RPC endpoint.
    pub rpc_url: String,
    /// Federation peg-in script (hex).
    pub federation_script: String,
    /// Peg address for deposits.
    pub peg_address: String,
    /// Required mainchain confirmations for peg-in.
    pub peg_in_confirmations: u64,
    /// Required Liquid confirmations for peg-out (2 of 3 functionaries).
    pub peg_out_confirmations: u64,
}

impl Default for LiquidConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:7041"),
            federation_script: String::new(),
            peg_address: String::new(),
            peg_in_confirmations: 102,
            peg_out_confirmations: 2,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcPegDeposit {
    commitment: String,
    amount: u64,
    mainchain_tx_id: String,
    confirmations: u64,
}

/// Peg-in operation status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegInStatus {
    /// Bitcoin mainchain txid.
    pub mainchain_tx_id: String,
    /// Liquid sidechain claim txid (None if not yet claimed).
    pub sidechain_tx_id: Option<String>,
    /// Confirmations on mainchain.
    pub mainchain_confs: u64,
    /// Whether the peg-in is matured and claimable.
    pub matured: bool,
}

/// Watchman federation status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchmanStatus {
    /// Number of active watchmen.
    pub active_watchmen: u32,
    /// Required signatures (threshold).
    pub threshold: u32,
    /// Current block height on Liquid.
    pub block_height: u64,
    /// Whether the federation is healthy.
    pub healthy: bool,
}

/// Liquid federation info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationInfo {
    /// Federation members (hex public keys).
    pub members: Vec<String>,
    /// Current signing threshold.
    pub threshold: u32,
    /// Peg-in address.
    pub peg_address: String,
}

/// Confidential transaction info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialTx {
    /// Transaction ID.
    pub txid: String,
    /// Number of inputs.
    pub inputs: u32,
    /// Number of outputs.
    pub outputs: u32,
    /// Whether the transaction uses confidential amounts.
    pub confidential: bool,
    /// Block height (0 if unconfirmed).
    pub block_height: u64,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Liquid Network bridge adapter.
bridge_boilerplate!(LiquidBridge, LiquidConfig);

impl<T: RpcTransport> LiquidBridge<T> {
    pub fn get_peg_in_status(&self, mainchain_txid: &str) -> Result<PegInStatus, BridgeError> {
        let result = self.rpc_call(
            "liquid_getPegInStatus",
            serde_json::json!([mainchain_txid]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse peg-in status: {e}")))
    }

    /// Get current watchman (functionary) status.
    pub fn get_watchman_status(&self) -> Result<WatchmanStatus, BridgeError> {
        let result = self.rpc_call("liquid_getWatchmanStatus", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse watchman status: {e}")))
    }

    /// Get federation info.
    pub fn get_federation_info(&self) -> Result<FederationInfo, BridgeError> {
        let result = self.rpc_call("liquid_getFederationInfo", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse federation info: {e}")))
    }

    /// Get confidential transaction details.
    pub fn get_confidential_tx(&self, txid: &str) -> Result<ConfidentialTx, BridgeError> {
        let result = self.rpc_call(
            "liquid_getConfidentialTx",
            serde_json::json!([txid]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse ct: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for LiquidBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("liquid_getPegDeposits", serde_json::json!([]))?;
        if result.is_null() { return Ok(vec![]); }
        let deposits: Vec<RpcPegDeposit> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse deposits: {e}")))?;
        deposits
            .into_iter()
            .filter(|d| d.confirmations >= self.config.peg_in_confirmations)
            .map(|d| {
                let commitment = hex_to_field(&d.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&d.mainchain_tx_id)
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
            "liquid_initiatePegOut",
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
        let txid = result["txid"]
            .as_str()
            .ok_or_else(|| BridgeError::WithdrawFailed("missing txid".into()))?;
        hex::decode(txid)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid txid hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "liquid_commitStateRoot",
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
            "liquid_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("liquid_getRemoteNullifierRoots", serde_json::json!([]))?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for LiquidBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "liquid_verifyProof",
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
        let cfg = LiquidConfig::default();
        assert_eq!(cfg.peg_in_confirmations, 102);
        assert_eq!(cfg.peg_out_confirmations, 2);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = LiquidBridge::new(LiquidConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = LiquidBridge::new(LiquidConfig::default());
        assert_eq!(bridge.config().peg_in_confirmations, 102);
    }
}
