//! Configuration types for the BitVM bridge.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default challenge timeout in Bitcoin blocks (~1 day).
pub const DEFAULT_CHALLENGE_TIMEOUT_BLOCKS: u32 = 144;

/// Default operator bond in satoshis (0.1 BTC).
pub const DEFAULT_BOND_SATS: u64 = 10_000_000;

/// Default minimum confirmations before considering a deposit final.
pub const DEFAULT_MIN_CONFIRMATIONS: u32 = 6;

/// A zeroize-on-drop wrapper for a 32-byte secret key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub [u8; 32]);

impl std::fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKeyBytes([REDACTED])")
    }
}

/// Configuration for the BitVM bridge operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitvmConfig {
    /// Bitcoin Core JSON-RPC URL.
    pub bitcoin_rpc_url: String,
    /// Operator's secret key (32-byte). Zeroized on drop.
    #[serde(skip)]
    pub operator_secret_key: Option<SecretKeyBytes>,
    /// Bond amount in satoshis staked per assertion.
    pub bond_sats: u64,
    /// Number of blocks the challenger has to dispute an assertion.
    pub challenge_timeout_blocks: u32,
    /// Required Bitcoin confirmations for deposit finality.
    pub min_confirmations: u32,
    /// Maximum number of pending assertions before blocking new ones.
    pub max_pending_assertions: usize,
}

impl Default for BitvmConfig {
    fn default() -> Self {
        Self {
            bitcoin_rpc_url: "http://127.0.0.1:18443".into(),
            operator_secret_key: None,
            bond_sats: DEFAULT_BOND_SATS,
            challenge_timeout_blocks: DEFAULT_CHALLENGE_TIMEOUT_BLOCKS,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            max_pending_assertions: 64,
        }
    }
}

/// Configuration for a standalone BitVM challenger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengerConfig {
    /// Bitcoin Core JSON-RPC URL.
    pub bitcoin_rpc_url: String,
    /// Challenger's secret key (32-byte). Zeroized on drop.
    #[serde(skip)]
    pub challenger_secret_key: Option<SecretKeyBytes>,
    /// Polling interval in seconds for watching operator assertions.
    pub watch_interval_secs: u64,
    /// Minimum profit (sats) required before challenging (bond - fees).
    pub min_profit_sats: u64,
}

impl Default for ChallengerConfig {
    fn default() -> Self {
        Self {
            bitcoin_rpc_url: "http://127.0.0.1:18443".into(),
            challenger_secret_key: None,
            watch_interval_secs: 30,
            min_profit_sats: 50_000,
        }
    }
}
