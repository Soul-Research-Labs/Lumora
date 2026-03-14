//! Rooch Network bridge adapter — MoveOS-based Bitcoin application layer.
//!
//! Rooch is a modular application layer for Bitcoin that uses MoveOS
//! for smart-contract execution. It can parse Bitcoin inscriptions
//! and UTXO data natively, enabling inscription-based deposits and
//! Move-based state verification.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Rooch Network bridge adapter.
#[derive(Debug, Clone)]
pub struct RoochConfig {
    /// Rooch JSON-RPC endpoint.
    pub rpc_url: String,
    /// Move module address for the Lumora bridge contract.
    pub move_module_address: String,
    /// Session key for authenticated operations (hex).
    pub session_key: String,
    /// Required confirmations.
    pub confirmations: u64,
}

impl Default for RoochConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:6767"),
            move_module_address: String::from("0x1"),
            session_key: String::new(),
            confirmations: 6,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcInscriptionDeposit {
    commitment: String,
    amount: u64,
    inscription_id: String,
    tx_id: String,
}

/// Move object state from Rooch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectState {
    /// Object ID.
    pub object_id: String,
    /// Object type tag (Move struct).
    pub object_type: String,
    /// Serialized object value (hex).
    pub value_hex: String,
    /// Owner address.
    pub owner: String,
    /// State root hash.
    pub state_root: String,
}

/// Result of a Move function call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveCallResult {
    /// Return values (hex-encoded BCS).
    pub return_values: Vec<String>,
    /// Gas used.
    pub gas_used: u64,
    /// Status: "Executed" or error.
    pub status: String,
}

/// Session key info for authenticated RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session key (hex).
    pub session_key: String,
    /// Expiry timestamp (unix seconds).
    pub expiry: u64,
    /// Max gas budget remaining.
    pub max_gas: u64,
    /// Whether the session is still valid.
    pub active: bool,
}

/// Bitcoin inscription detected by Rooch indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InscriptionInfo {
    /// Inscription ID (txid:index).
    pub inscription_id: String,
    /// Content type MIME.
    pub content_type: String,
    /// Content body (hex-encoded).
    pub body_hex: String,
    /// Bitcoin transaction ID.
    pub tx_id: String,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Rooch Network bridge adapter.
bridge_boilerplate!(RoochBridge, RoochConfig);

impl<T: RpcTransport> RoochBridge<T> {
    pub fn get_object_state(&self, object_id: &str) -> Result<ObjectState, BridgeError> {
        let result = self.rpc_call(
            "rooch_getObjectStates",
            serde_json::json!([object_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse object state: {e}")))
    }

    /// Execute a read-only Move function call.
    pub fn execute_move_call(
        &self,
        function: &str,
        type_args: &[String],
        args: &[String],
    ) -> Result<MoveCallResult, BridgeError> {
        let result = self.rpc_call(
            "rooch_executeViewFunction",
            serde_json::json!({
                "function_id": format!("{}::{}", self.config.move_module_address, function),
                "ty_args": type_args,
                "args": args,
            }),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse move call: {e}")))
    }

    /// Get inscription-based deposits from the Rooch indexer.
    pub fn get_inscription_deposits(&self) -> Result<Vec<InscriptionInfo>, BridgeError> {
        let result = self.rpc_call(
            "rooch_getInscriptions",
            serde_json::json!({ "module": self.config.move_module_address }),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse inscriptions: {e}")))
    }

    /// Get session key info.
    pub fn get_session_info(&self) -> Result<SessionInfo, BridgeError> {
        let result = self.rpc_call(
            "rooch_getSessionInfo",
            serde_json::json!([self.config.session_key]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse session: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for RoochBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("rooch_getDeposits", serde_json::json!([]))?;
        if result.is_null() { return Ok(vec![]); }
        let deposits: Vec<RpcInscriptionDeposit> = serde_json::from_value(result)
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
            "rooch_executeTransaction",
            serde_json::json!({
                "function_id": format!("{}::bridge::withdraw", self.config.move_module_address),
                "args": [
                    withdrawal.amount.to_string(),
                    hex::encode(withdrawal.recipient),
                    hex::encode(&withdrawal.proof_bytes),
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
                "session_key": self.config.session_key,
            }),
        )?;
        let tx_hash = result["tx_hash"]
            .as_str()
            .ok_or_else(|| BridgeError::WithdrawFailed("missing tx_hash".into()))?;
        hex::decode(tx_hash)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid tx hash hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "rooch_executeTransaction",
            serde_json::json!({
                "function_id": format!("{}::bridge::commit_root", self.config.move_module_address),
                "args": [field_to_hex(&root)],
                "session_key": self.config.session_key,
            }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: u64,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        self.rpc_call(
            "rooch_executeTransaction",
            serde_json::json!({
                "function_id": format!("{}::bridge::commit_nullifier_root", self.config.move_module_address),
                "args": [epoch_id.to_string(), field_to_hex(&root)],
                "session_key": self.config.session_key,
            }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call(
            "rooch_executeViewFunction",
            serde_json::json!({
                "function_id": format!("{}::bridge::remote_nullifier_roots", self.config.move_module_address),
                "ty_args": [],
                "args": [],
            }),
        )?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(
            result.get("return_values").cloned().unwrap_or(serde_json::json!([])),
        )
        .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for RoochBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "rooch_verifyProof",
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
        let cfg = RoochConfig::default();
        assert_eq!(cfg.confirmations, 6);
        assert_eq!(cfg.move_module_address, "0x1");
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = RoochBridge::new(RoochConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = RoochBridge::new(RoochConfig::default());
        assert_eq!(bridge.config().confirmations, 6);
    }
}
