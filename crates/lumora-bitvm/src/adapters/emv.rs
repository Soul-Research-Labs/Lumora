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
            merchant_id: String::from("sandbox-merchant"),
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
    fn validate_config(&self) -> Result<(), BridgeError> {
        if self.config.network_id.trim().is_empty() {
            return Err(BridgeError::ConnectionError(
                "invalid config: network_id must not be empty".into(),
            ));
        }
        if self.config.merchant_id.trim().is_empty() {
            return Err(BridgeError::ConnectionError(
                "invalid config: merchant_id must not be empty".into(),
            ));
        }
        if self.config.currency.trim().is_empty() {
            return Err(BridgeError::ConnectionError(
                "invalid config: currency must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// Query payment status for a specific EMV payment id.
    pub fn get_payment_status(&self, payment_id: &str) -> Result<RpcEmvPaymentStatus, BridgeError> {
        self.validate_config()?;
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
        self.validate_config()?;
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
            .filter(|d| d.finality >= self.config.min_finality)
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
        self.validate_config()?;
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

        if !payout.status.eq_ignore_ascii_case("accepted")
            && !payout.status.eq_ignore_ascii_case("settled")
        {
            return Err(BridgeError::WithdrawFailed(format!(
                "gateway rejected payout with status '{}'",
                payout.status
            )));
        }

        hex::decode(&payout.payout_id)
            .map_err(|e| BridgeError::WithdrawFailed(format!("invalid payout_id hex: {e}")))
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        self.validate_config()?;
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
        self.validate_config()?;
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
        self.validate_config()?;
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
        self.validate_config()?;
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
    use super::super::mock::MockTransport;

    #[test]
    fn default_config() {
        let cfg = EmvConfig::default();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:9400");
        assert_eq!(cfg.network_id, "sandbox");
        assert_eq!(cfg.merchant_id, "sandbox-merchant");
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

    #[test]
    fn mock_poll_deposits() {
        let commitment = field_to_hex(&pallas::Base::from(42u64));
        let transport = MockTransport::new().on(
            "emv_getSettledQrPayments",
            serde_json::json!([
                {
                    "commitment": commitment,
                    "amount": 25000,
                    "payment_id": "ab".repeat(32),
                    "finality": 3
                }
            ]),
        );

        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        let deposits = bridge.poll_deposits().unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].amount, 25000);
        assert_eq!(deposits[0].tx_id.len(), 32);
    }

    #[test]
    fn mock_poll_deposits_filters_low_finality() {
        let commitment = field_to_hex(&pallas::Base::from(42u64));
        let mut cfg = EmvConfig::default();
        cfg.min_finality = 3;
        let transport = MockTransport::new().on(
            "emv_getSettledQrPayments",
            serde_json::json!([
                {
                    "commitment": commitment,
                    "amount": 25000,
                    "payment_id": "ab".repeat(32),
                    "finality": 2
                }
            ]),
        );

        let bridge = EmvBridge::with_transport(cfg, transport);
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn mock_poll_deposits_rejects_invalid_payment_id() {
        let commitment = field_to_hex(&pallas::Base::from(42u64));
        let transport = MockTransport::new().on(
            "emv_getSettledQrPayments",
            serde_json::json!([
                {
                    "commitment": commitment,
                    "amount": 25000,
                    "payment_id": "not_hex",
                    "finality": 3
                }
            ]),
        );

        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        let result = bridge.poll_deposits();
        assert!(result.is_err());
    }

    #[test]
    fn mock_execute_withdrawal() {
        let transport = MockTransport::new().on(
            "emv_submitPayout",
            serde_json::json!({
                "payout_id": "cc".repeat(32),
                "status": "ACCEPTED"
            }),
        );
        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        let wd = OutboundWithdrawal {
            amount: 100_000,
            recipient: [0xAA; 32],
            proof_bytes: vec![1, 2, 3, 4],
            nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
        };

        let tx_id = bridge.execute_withdrawal(&wd).unwrap();
        assert_eq!(tx_id.len(), 32);
    }

    #[test]
    fn mock_execute_withdrawal_rejected_status() {
        let transport = MockTransport::new().on(
            "emv_submitPayout",
            serde_json::json!({
                "payout_id": "cc".repeat(32),
                "status": "rejected"
            }),
        );
        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        let wd = OutboundWithdrawal {
            amount: 100_000,
            recipient: [0xAA; 32],
            proof_bytes: vec![1, 2, 3, 4],
            nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
        };

        let result = bridge.execute_withdrawal(&wd);
        assert!(result.is_err());
    }

    #[test]
    fn mock_commit_state_root() {
        let transport = MockTransport::new().on("emv_commitStateRoot", serde_json::json!(true));
        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        assert!(bridge.commit_state_root(pallas::Base::zero()).is_ok());
    }

    #[test]
    fn mock_verify_proof_true() {
        let transport = MockTransport::new().on("emv_verifyProof", serde_json::json!(true));
        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        assert!(bridge.verify_proof(&[1u8; 32], &[]).unwrap());
    }

    #[test]
    fn mock_fetch_remote_nullifier_roots_error() {
        let transport = MockTransport::new().on(
            "emv_getRemoteNullifierRoots",
            serde_json::json!([
                { "chain_id": 1, "epoch_id": 3, "root": "invalid_hex" }
            ]),
        );
        let bridge = EmvBridge::with_transport(EmvConfig::default(), transport);
        let result = bridge.fetch_remote_nullifier_roots();
        assert!(result.is_err());
    }

    #[test]
    fn poll_deposits_fails_with_empty_merchant_id() {
        let mut cfg = EmvConfig::default();
        cfg.merchant_id.clear();
        let bridge = EmvBridge::new(cfg);
        let result = bridge.poll_deposits();
        assert!(result.is_err());
    }
}
