//! Lightning Network bridge adapter — Channel-based instant BTC transfers.
//!
//! Integrates with Lightning Network nodes (LND-compatible API) for
//! instant, channel-based Bitcoin transfers. Deposits are funded via
//! channel opens or invoice payments; withdrawals create HTLC-locked
//! payments. Works alongside BitVM for dispute resolution.

use std::cell::Cell;

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, RpcTransport};

use super::{field_to_hex, hex_to_field};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Lightning Network bridge adapter.
#[derive(Debug, Clone)]
pub struct LightningConfig {
    /// LND-compatible REST/gRPC endpoint.
    pub rpc_url: String,
    /// Macaroon for authentication (hex-encoded).
    pub macaroon_hex: String,
    /// Minimum channel capacity in satoshis.
    pub min_channel_capacity_sats: u64,
    /// HTLC timeout in blocks.
    pub htlc_timeout_blocks: u32,
    /// Maximum in-flight HTLC value (sats).
    pub max_htlc_value_sats: u64,
}

impl Default for LightningConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("https://127.0.0.1:8080"),
            macaroon_hex: String::new(),
            min_channel_capacity_sats: 100_000,
            htlc_timeout_blocks: 144,
            max_htlc_value_sats: 10_000_000,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcInvoiceDeposit {
    commitment: String,
    amount: u64,
    payment_hash: String,
}

/// Lightning channel info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// Channel identifier.
    pub channel_id: String,
    /// Remote node public key.
    pub remote_pubkey: String,
    /// Channel capacity in satoshis.
    pub capacity_sats: u64,
    /// Local balance in satoshis.
    pub local_balance_sats: u64,
    /// Remote balance in satoshis.
    pub remote_balance_sats: u64,
    /// Whether the channel is active.
    pub active: bool,
}

/// HTLC event emitted by the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcEvent {
    /// Payment hash.
    pub payment_hash: String,
    /// Amount in milli-satoshis.
    pub amount_msat: u64,
    /// Type: "send", "receive", "forward".
    pub event_type: String,
    /// Settled flag.
    pub settled: bool,
}

/// Lightning invoice details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    /// BOLT-11 payment request string.
    pub payment_request: String,
    /// Payment hash (hex).
    pub payment_hash: String,
    /// Value in satoshis.
    pub value_sats: u64,
    /// Memo / description.
    pub memo: String,
    /// Whether the invoice has been settled.
    pub settled: bool,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Lightning Network bridge adapter.
pub struct LightningBridge<T: RpcTransport = OfflineTransport> {
    config: LightningConfig,
    transport: T,
    next_id: Cell<u64>,
}

impl LightningBridge<OfflineTransport> {
    pub fn new(config: LightningConfig) -> Self {
        Self {
            config,
            transport: OfflineTransport,
            next_id: Cell::new(1),
        }
    }
}

impl<T: RpcTransport> LightningBridge<T> {
    pub fn with_transport(config: LightningConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            next_id: Cell::new(1),
        }
    }

    pub fn config(&self) -> &LightningConfig {
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

    /// Create a Lightning invoice for deposits.
    pub fn create_invoice(
        &self,
        amount_sats: u64,
        memo: &str,
    ) -> Result<Invoice, BridgeError> {
        let result = self.rpc_call(
            "ln_addInvoice",
            serde_json::json!({ "value": amount_sats, "memo": memo }),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse invoice: {e}")))
    }

    /// Pay a Lightning invoice (outgoing).
    pub fn pay_invoice(&self, payment_request: &str) -> Result<HtlcEvent, BridgeError> {
        let result = self.rpc_call(
            "ln_sendPayment",
            serde_json::json!({ "payment_request": payment_request }),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse payment: {e}")))
    }

    /// List active channels.
    pub fn list_channels(&self) -> Result<Vec<ChannelInfo>, BridgeError> {
        let result = self.rpc_call("ln_listChannels", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse channels: {e}")))
    }

    /// Get total channel balance (local side) in satoshis.
    pub fn get_channel_balance(&self) -> Result<u64, BridgeError> {
        let result = self.rpc_call("ln_channelBalance", serde_json::json!([]))?;
        result["balance"]
            .as_u64()
            .ok_or_else(|| BridgeError::ConnectionError("missing balance".into()))
    }
}

impl<T: RpcTransport> RollupBridge for LightningBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("ln_getSettledInvoices", serde_json::json!([]))?;
        if result.is_null() { return Ok(vec![]); }
        let deposits: Vec<RpcInvoiceDeposit> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse invoices: {e}")))?;
        deposits
            .into_iter()
            .map(|d| {
                let commitment = hex_to_field(&d.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&d.payment_hash)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad hash: {e}")))?;
                Ok(InboundDeposit { commitment, amount: d.amount, tx_id })
            })
            .collect()
    }

    fn execute_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "ln_executeWithdrawal",
            serde_json::json!({
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
                "htlc_timeout": self.config.htlc_timeout_blocks,
            }),
        )?;
        let hash = result["payment_hash"]
            .as_str()
            .ok_or_else(|| BridgeError::WithdrawFailed("missing payment_hash".into()))?;
        hex::decode(hash)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid hash hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "ln_commitStateRoot",
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
            "ln_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("ln_getRemoteNullifierRoots", serde_json::json!([]))?;
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
        let cfg = LightningConfig::default();
        assert_eq!(cfg.min_channel_capacity_sats, 100_000);
        assert_eq!(cfg.htlc_timeout_blocks, 144);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = LightningBridge::new(LightningConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = LightningBridge::new(LightningConfig::default());
        assert_eq!(bridge.config().max_htlc_value_sats, 10_000_000);
    }
}
