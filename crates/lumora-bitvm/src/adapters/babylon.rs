//! Babylon bridge adapter — Bitcoin staking protocol with finality gadget.
//!
//! Babylon enables Bitcoin holders to stake BTC to secure PoS chains via
//! a finality gadget. This adapter integrates with Babylon's staking
//! infrastructure, enabling Lumora to use staking deposits, slashing
//! proofs (verified via BitVM), and finality signatures.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::rollup::{JsonRpcRequest, OfflineTransport, OnChainVerifier, RpcTransport};

use super::{bridge_boilerplate, field_to_hex, hex_to_field, parse_remote_nullifier_roots, sha256};

// ─── Configuration ──────────────────────────────────────────────────────

/// Configuration for the Babylon bridge adapter.
#[derive(Debug, Clone)]
pub struct BabylonConfig {
    /// Babylon node RPC endpoint.
    pub rpc_url: String,
    /// Babylon chain ID.
    pub chain_id: u64,
    /// Required L1 confirmations for deposit finality.
    pub confirmations: u64,
    /// Staking contract address on the Babylon chain.
    pub staking_contract_address: String,
    /// Finality gadget service URL.
    pub finality_gadget_url: String,
    /// Minimum staking amount in satoshis.
    pub min_staking_sats: u64,
    /// Staking lock time in Bitcoin blocks.
    pub staking_lock_blocks: u32,
}

impl Default for BabylonConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::from("http://127.0.0.1:26657"),
            chain_id: 1,
            confirmations: 10,
            staking_contract_address: String::new(),
            finality_gadget_url: String::from("http://127.0.0.1:26658"),
            min_staking_sats: 50_000,
            staking_lock_blocks: 64000,
        }
    }
}

// ─── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct RpcDeposit {
    commitment: String,
    amount: u64,
    tx_id: String,
    staking_tx_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcWithdrawalResult {
    tx_id: String,
    unbonding_tx_hash: String,
}

/// Babylon validator set information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Active validator public keys (hex-encoded).
    pub validators: Vec<ValidatorInfo>,
    /// Total staked BTC across all validators (satoshis).
    pub total_staked_sats: u64,
    /// Current epoch number.
    pub epoch: u64,
}

/// Individual validator information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator BTC public key (hex-encoded).
    pub btc_pubkey: String,
    /// Amount staked by this validator (satoshis).
    pub staked_sats: u64,
    /// Whether the validator is active.
    pub active: bool,
    /// Commission rate (basis points).
    pub commission_bps: u32,
}

/// Staking parameters from the Babylon network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingParams {
    /// Minimum staking amount (satoshis).
    pub min_staking_sats: u64,
    /// Maximum staking amount (satoshis).
    pub max_staking_sats: u64,
    /// Minimum staking duration (Bitcoin blocks).
    pub min_staking_blocks: u32,
    /// Maximum staking duration (Bitcoin blocks).
    pub max_staking_blocks: u32,
    /// Slashing penalty rate (basis points).
    pub slashing_rate_bps: u32,
    /// Unbonding time in Bitcoin blocks.
    pub unbonding_blocks: u32,
}

/// BTC delegation status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationStatus {
    /// Staking transaction hash on Bitcoin.
    pub staking_tx_hash: String,
    /// State: "pending", "active", "unbonding", "withdrawn", "slashed".
    pub state: String,
    /// Amount staked (satoshis).
    pub staked_sats: u64,
    /// Block height at which staking becomes active.
    pub activation_height: u64,
    /// Block height at which unbonding completes (if unbonding).
    pub unbonding_height: Option<u64>,
}

/// Finality signature submission receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityReceipt {
    /// Block hash that was finalized.
    pub block_hash: String,
    /// Block height.
    pub block_height: u64,
    /// Whether the signature was accepted.
    pub accepted: bool,
}

// ─── Bridge ─────────────────────────────────────────────────────────────

/// Babylon bridge adapter.
bridge_boilerplate!(BabylonBridge, BabylonConfig);

impl<T: RpcTransport> BabylonBridge<T> {
    pub fn get_validator_set(&self) -> Result<ValidatorSet, BridgeError> {
        let result = self.rpc_call("babylon_getValidatorSet", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse validator set: {e}")))
    }

    /// Submit a finality signature for a block.
    pub fn submit_finality_signature(
        &self,
        block_hash: &str,
        signature: &str,
        signer_pubkey: &str,
    ) -> Result<FinalityReceipt, BridgeError> {
        let result = self.rpc_call(
            "babylon_submitFinalitySignature",
            serde_json::json!({
                "block_hash": block_hash,
                "signature": signature,
                "signer_pubkey": signer_pubkey,
            }),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse finality receipt: {e}")))
    }

    /// Get staking parameters from the Babylon chain.
    pub fn get_staking_params(&self) -> Result<StakingParams, BridgeError> {
        let result = self.rpc_call("babylon_getStakingParams", serde_json::json!([]))?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse staking params: {e}")))
    }

    /// Get the delegation status for a specific staking transaction.
    pub fn get_btc_delegation_status(
        &self,
        staking_tx_hash: &str,
    ) -> Result<DelegationStatus, BridgeError> {
        let result = self.rpc_call(
            "babylon_getBtcDelegationStatus",
            serde_json::json!([staking_tx_hash]),
        )?;
        serde_json::from_value(result)
            .map_err(|e| BridgeError::ConnectionError(format!("parse delegation status: {e}")))
    }
}

impl<T: RpcTransport> RollupBridge for BabylonBridge<T> {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        let result = self.rpc_call("babylon_getStakingDeposits", serde_json::json!([]))?;        if result.is_null() { return Ok(vec![]); }        let deposits: Vec<RpcDeposit> = serde_json::from_value(result)
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
            "babylon_submitSlashingProof",
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
            "babylon_commitFinalityRoot",
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
            "babylon_commitNullifierEpochRoot",
            serde_json::json!({ "epoch_id": epoch_id, "root": field_to_hex(&root) }),
        )?;
        Ok(())
    }

    fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        let result = self.rpc_call("babylon_getRemoteNullifierRoots", serde_json::json!([]))?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result)
            .map_err(|e| BridgeError::NullifierSyncFailed(format!("parse: {e}")))?;
        parse_remote_nullifier_roots(entries)
    }
}

impl<T: RpcTransport> OnChainVerifier for BabylonBridge<T> {
    fn verify_proof(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &[pallas::Base],
    ) -> Result<bool, BridgeError> {
        let proof_hash = hex::encode(sha256(proof_bytes));
        let result = self.rpc_call(
            "babylon_verifySlashingProof",
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
        let cfg = BabylonConfig::default();
        assert_eq!(cfg.confirmations, 10);
        assert_eq!(cfg.min_staking_sats, 50_000);
        assert_eq!(cfg.staking_lock_blocks, 64000);
    }

    #[test]
    fn offline_poll_deposits() {
        let bridge = BabylonBridge::new(BabylonConfig::default());
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn config_accessor() {
        let bridge = BabylonBridge::new(BabylonConfig::default());
        assert_eq!(bridge.config().min_staking_sats, 50_000);
    }

    #[test]
    fn default_staking_params_reasonable() {
        let cfg = BabylonConfig::default();
        assert!(cfg.staking_lock_blocks > 0);
        assert!(cfg.min_staking_sats > 0);
    }
}
