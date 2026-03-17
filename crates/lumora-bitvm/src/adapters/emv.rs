//! EMVCo QR bridge adapter.
//!
//! Integrates an EMVCo QR payment gateway through Lumora's bridge adapter model.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

/// Configuration for the EMVCo QR bridge adapter.
#[derive(Debug, Clone)]
pub struct EmvConfig {
    /// EMV gateway JSON-RPC endpoint.
    pub rpc_url: String,
    /// Network identifier for the EMV provider environment.
    pub network_id: String,
    /// Merchant identifier registered with the EMV gateway.
    pub merchant_id: String,
    /// Minimum gateway finality units before a payment is treated as settled.
    pub min_finality: u64,
    /// Transaction currency code (ISO 4217-style, provider-defined).
    pub currency: String,
}

impl Default for EmvConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:9400"),
            network_id: String::from("sandbox"),
            merchant_id: String::new(),
            min_finality: 1,
            currency: String::from("BTC"),
        }
    }
}

/// Inbound QR payment record returned by EMV gateway polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEmvDeposit {
    pub commitment: String,
    pub amount: u64,
    pub payment_id: String,
    pub finality: u64,
}

/// Outbound payout result returned by EMV gateway execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEmvWithdrawalResult {
    pub payout_id: String,
    pub status: String,
}

/// Payment status returned by the EMV gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEmvPaymentStatus {
    pub payment_id: String,
    pub status: String,
    pub finality: u64,
}

bridge_boilerplate!(EmvBridge, EmvConfig);

impl<T: RpcTransport> EmvBridge<T> {
    /// Query payment status for a specific EMV payment id.
    pub fn get_payment_status(&self, payment_id: &str) -> Result<RpcEmvPaymentStatus, BridgeError> {
        let result = self.rpc_call(
            "emv_getPaymentStatus",
            serde_json::json!({
                "payment_id": payment_id,
                "network_id": self.config.network_id,
                "merchant_id": self.config.merchant_id,
            }),
        )?;

        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse payment status: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for EmvBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call(
            "emv_getSettledQrPayments",
            serde_json::json!({
                "network_id": self.config.network_id,
                "merchant_id": self.config.merchant_id,
                "min_finality": self.config.min_finality,
                "currency": self.config.currency,
            }),
        )?;
        if result.is_null() {
            return Ok(vec![]);
        }

        let deposits: Vec<RpcEmvDeposit> = serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse settled payments: {e}")))?;

        deposits
            .into_iter()
            .map(|d| {
                let commitment = hex_to_field(&d.commitment)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad commitment: {e}")))?;
                let tx_id = hex::decode(&d.payment_id)
                    .map_err(|e| BridgeError::DepositRejected(format!("bad payment_id: {e}")))?;

                Ok(InboundDeposit {
                    commitment,
                    amount: d.amount,
                    tx_id,
                })
            })
            .collect()
    }

    fn execute_withdrawal(&self, withdrawal: &OutboundWithdrawal) -> Result<Vec<u8>, BridgeError> {
        let result = self.rpc_call(
            "emv_submitPayout",
            serde_json::json!({
                "network_id": self.config.network_id,
                "merchant_id": self.config.merchant_id,
                "currency": self.config.currency,
                "amount": withdrawal.amount,
                "recipient": hex::encode(withdrawal.recipient),
                "proof_bytes": hex::encode(&withdrawal.proof_bytes),
                "nullifiers": [
                    field_to_hex(&withdrawal.nullifiers[0]),
                    field_to_hex(&withdrawal.nullifiers[1]),
                ],
            }),
        )?;

        let payout: RpcEmvWithdrawalResult = serde_json::from_value(result)
            .map_err(|e| BridgeError::WithdrawFailed(format!("parse payout result: {e}")))?;

        if payout.status != "accepted" && payout.status != "settled" {
            return Err(BridgeError::WithdrawFailed(format!(
                "gateway rejected payout with status '{}'",
                payout.status
            )));
        }

        hex::decode(&payout.payout_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid payout_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "emv_commitStateRoot",
            serde_json::json!({
                "network_id": self.config.network_id,
                "merchant_id": self.config.merchant_id,
                "root": field_to_hex(&root),
            }),
        )?;
        Ok(())
    }

    fn commit_nullifier_epoch_root(&self, epoch_id: u64, root: pallas::Base) -> Result<(), BridgeError> {
        self.rpc_call(
            "emv_commitNullifierEpochRoot",
            serde_json::json!({
                "network_id": self.config.network_id,
                "merchant_id": self.config.merchant_id,
                "epoch_id": epoch_id,
                "root": field_to_hex(&root),
            }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call(
            "emv_getRemoteNullifierRoots",
            serde_json::json!({
                "network_id": self.config.network_id,
            }),
        )?;

        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;

        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for EmvBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "emv_verifyProof",
            serde_json::json!({
                "network_id": self.config.network_id,
                "proof_hash": proof_hash,
            }),
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
        let cfg = EmvConfig::default();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:9400");
        assert_eq!(cfg.network_id, "sandbox");
        assert_eq!(cfg.min_finality, 1);
        assert_eq!(cfg.currency, "BTC");
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = EmvBridge::new(EmvConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = EmvBridge::new(EmvConfig::default());
        assert_eq!(bridge.config().network_id, "sandbox");
    }
}
