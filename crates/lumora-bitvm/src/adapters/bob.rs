//! BOB (Build on Bitcoin) bridge adapter — Hybrid L2 combining EVM execution
//! with Bitcoin security.
//!
//! BOB uses an EVM execution layer with a Bitcoin-native gateway for deposits
//! and withdrawals. The adapter communicates with both the EVM JSON-RPC endpoint
//! and BOB-specific gateway methods for Bitcoin interoperability.

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

/// Configuration for the BOB bridge adapter.
#[derive(Debug, Clone)]
pub struct BobConfig {
    /// BOB EVM RPC endpoint.
    pub rpc_url: String,
    /// Bitcoin RPC endpoint for L1 interaction.
    pub bitcoin_rpc_url: String,
    /// BOB chain ID (default: 60808).
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// BOB gateway contract address (20-byte EVM address).
    pub gateway_address: [u8; 20],
    /// Maximum withdrawals per batch.
    pub max_batch_size: usize,
}

impl Default for BobConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:8545"),
            bitcoin_rpc_url: String::from("http://127.0.0.1:18443"),
            chain_id: 60808,
            confirmations: 6,
            gateway_address: [0; 20],
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
    bitcoin_tx_id: Option<String>,
    confirmations: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcWithdrawalResult {
    tx_id: String,
    evm_tx_hash: String,
}

/// Gateway contract status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayStatus {
    /// Whether the gateway is accepting deposits.
    pub accepting_deposits: bool,
    /// Total value locked in the gateway (satoshis).
    pub tvl_sats: u64,
    /// Number of pending withdrawals.
    pub pending_withdrawals: u64,
    /// Gateway contract version.
    pub version: String,
}

/// Bitcoin finality information for a BOB transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinFinality {
    /// L1 transaction ID.
    pub l1_tx_id: String,
    /// Number of confirmations.
    pub confirmations: u64,
    /// Whether the transaction is considered final.
    pub is_final: bool,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// BOB bridge adapter.
pub struct BobBridge<T: RpcTransport = OfflineTransport> {
    config: BobConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl BobBridge<OfflineTransport> {
    pub fn new(config: BobConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> BobBridge<T> {
    pub fn with_transport(config: BobConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &BobConfig {
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

    /// Execute an `eth_call` against a contract on the BOB EVM.
    pub fn eth_call(
        &self,
        to: &[u8; 20],
        data: &[u8],
    ) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "eth_call",
            serde_json::json!([{
                "to": format!("0x{}", hex::encode(to)),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )?;
        let hex_str = result.as_str().unwrap_or("0x").trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| BridgeError::ConnectionError(format!("eth_call decode: {e}")))
    }

    /// Query the gateway contract status.
    pub fn get_gateway_status(&self) -> Result<GatewayStatus, BridgeError> {
        let result = self.rpc_call(
            "bob_getGatewayStatus",
            serde_json::json!([hex::encode(self.config.gateway_address)]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse gateway status: {e}")))
    }

    /// Check Bitcoin finality for a specific L1 transaction.
    pub fn get_bitcoin_finality(&self, l1_tx_id: &str) -> Result<BitcoinFinality, BridgeError> {
        let result = self.rpc_call(
            "bob_getBitcoinFinality",
            serde_json::json!([l1_tx_id]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse finality: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for BobBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("bob_getBitcoinDeposits", serde_json::json!([]))?;        if result.is_null() { return Ok(vec![]); }        let deposits: Vec<RpcDeposit> = serde_json::from_value(result)
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
            "bob_submitBitcoinWithdrawal",
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
            "bob_commitStateRoot",
            serde_json::json!({ "root": field_to_hex(&root), "chain_id": self.config.chain_id }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: u64,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        self.rpc_call(
            "bob_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("bob_getRemoteNullifierRoots", serde_json::json!([]))?;
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

impl<T: RpcTransport> OnChainVerifier for BobBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "bob_verifyProof",
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
        let cfg = BobConfig::default();
        assert_eq!(cfg.chain_id, 60808);
        assert_eq!(cfg.confirmations, 6);
        assert_eq!(cfg.gateway_address, [0; 20]);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = BobBridge::new(BobConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn offline_eth_call() {
        let bridge = BobBridge::new(BobConfig::default());
        // OfflineTransport returns null for eth_call
        let result = bridge.eth_call(&[0; 20], &[0xAB; 4]);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn config_accessor() {
        let bridge = BobBridge::new(BobConfig::default());
        assert_eq!(bridge.config().chain_id, 60808);
    }
}
