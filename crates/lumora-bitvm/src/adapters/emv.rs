//! EMVCo QR bridge adapter scaffold.
//!
//! This module introduces configuration and wire contracts for integrating
//! EMVCo QR payment rails via the existing RollupBridge adapter model.

use serde::{Deserialize, Serialize};

/// Configuration for the EMVCo QR bridge adapter.
#[derive(Debug, Clone)]
pub struct EmvConfig {
    /// EMV gateway JSON-RPC endpoint.
    pub rpc_url: String,
    /// Network identifier for the EMV provider environment.
    pub network_id: String,
    /// Merchant identifier registered with the EMV gateway.
    pub merchant_id: String,
    /// Minimum confirmations/finality units before a payment is treated as settled.
    pub min_finality: u64,
}

impl Default for EmvConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:9400"),
            network_id: String::from("sandbox"),
            merchant_id: String::new(),
            min_finality: 1,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = EmvConfig::default();
        assert_eq!(cfg.rpc_url, "http://127.0.0.1:9400");
        assert_eq!(cfg.network_id, "sandbox");
        assert_eq!(cfg.min_finality, 1);
    }
}
