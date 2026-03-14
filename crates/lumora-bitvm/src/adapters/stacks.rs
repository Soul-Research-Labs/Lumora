//! Stacks / sBTC bridge adapter — Smart contract L2 with sBTC Bitcoin peg.
//!
//! Stacks is a Bitcoin L2 with Clarity smart contracts and Proof-of-Transfer
//! (PoX) consensus. sBTC provides a 1:1 Bitcoin-backed peg managed by a
//! decentralized signer set. This adapter communicates with Stacks' API
//! for deposit/withdrawal via sBTC and Clarity contract interactions.

use std::cell::Cell;

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, RpcTransport};

use super::{field_to_hex, hex_to_field};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Stacks bridge adapter.
#[derive(Debug, Clone)]
pub struct StacksConfig {
    /// Stacks node RPC endpoint.
    pub rpc_url: String,
    /// Stacks chain ID (default: 1 for mainnet).
    pub chain_id: u64,
    /// Required Bitcoin confirmations for deposit finality.
    pub confirmations: u64,
    /// sBTC contract identifier (e.g. "SP3K8BC0...::sbtc-token").
    pub sbtc_contract_id: String,
    /// Lumora Clarity contract identifier for root commitments.
    pub clarity_contract_id: String,
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for StacksConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:20443"),
            chain_id: 1,
            confirmations: 6,
            sbtc_contract_id: String::new(),
            clarity_contract_id: String::new(),
            max_batch_size: 16,
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
    sbtc_burn_tx: String,
}

/// sBTC peg status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbtcPegStatus {
    /// Total sBTC supply in circulation (micro-sBTC).
    pub total_supply: u64,
    /// Total BTC locked in the peg (satoshis).
    pub btc_locked_sats: u64,
    /// Number of active sBTC signers.
    pub active_signers: u64,
    /// Required signatures for peg operations.
    pub threshold: u64,
    /// Whether the peg is accepting deposits.
    pub accepting_deposits: bool,
    /// Whether the peg is processing withdrawals.
    pub processing_withdrawals: bool,
}

/// Stacks block correlated with a Bitcoin burn block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StxBurnBlock {
    /// Stacks block height.
    pub stx_block_height: u64,
    /// Bitcoin burn block height.
    pub burn_block_height: u64,
    /// Stacks block hash (hex).
    pub stx_block_hash: String,
    /// Bitcoin block hash (hex).
    pub burn_block_hash: String,
}

/// Result of a Clarity readonly function call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarityCallResult {
    /// Whether the call succeeded.
    pub okay: bool,
    /// Hex-encoded Clarity value result.
    pub result: String,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Stacks / sBTC bridge adapter.
pub struct StacksBridge<T: RpcTransport = OfflineTransport> {
    config: StacksConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl StacksBridge<OfflineTransport> {
    pub fn new(config: StacksConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> StacksBridge<T> {
    pub fn with_transport(config: StacksConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &StacksConfig {
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

    /// Get the current sBTC peg status.
    pub fn get_sbtc_peg_status(&self) -> Result<SbtcPegStatus, BridgeError> {
        let result = self.rpc_call("stacks_getSbtcPegStatus", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse sBTC peg status: {e}")))
    }

    /// Get the Stacks block corresponding to a Bitcoin burn block height.
    pub fn get_stx_block_by_burn_block(
        &self,
        burn_block_height: u64,
    ) -> Result<StxBurnBlock, BridgeError> {
        let result = self.rpc_call(
            "stacks_getStxBlockByBurnBlock",
            serde_json::json!([burn_block_height]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse STX burn block: {e}")))
    }

    /// Call a Clarity contract function in readonly mode.
    pub fn call_clarity_readonly(
        &self,
        contract_id: &str,
        function_name: &str,
        args: &[String],
    ) -> Result<ClarityCallResult, BridgeError> {
        let result = self.rpc_call(
            "stacks_callClarityReadonly",
            serde_json::json!({
                "contract_id": contract_id,
                "function_name": function_name,
                "args": args,
            }),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse Clarity result: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for StacksBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("stacks_getStxDeposits", serde_json::json!([]))?;        if result.is_null() { return Ok(vec![]); }        let deposits: Vec<RpcDeposit> = serde_json::from_value(result)
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
            "stacks_submitSbtcWithdrawal",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
                "sbtc_contract": self.config.sbtc_contract_id,
            }),
        )?;
        let wr: RpcWithdrawalResult = serde_json::from_value(result)
            .map_err(|e| BridgeError::WithdrawFailed(format!("parse result: {e}")))?;
        hex::decode(&wr.tx_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid tx_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "stacks_commitClarityRoot",
            serde_json::json!({
                "root": field_to_hex(&root),
                "contract_id": self.config.clarity_contract_id,
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
            "stacks_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("stacks_getRemoteNullifierRoots", serde_json::json!([]))?;
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
        let cfg = StacksConfig::default();
        assert_eq!(cfg.chain_id, 1);
        assert_eq!(cfg.max_batch_size, 16);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = StacksBridge::new(StacksConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = StacksBridge::new(StacksConfig::default());
        assert_eq!(bridge.config().chain_id, 1);
    }
}
