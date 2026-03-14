//! `BitvmBridge` — `RollupBridge` implementation backed by BitVM2 on Bitcoin L1.
//!
//! This bridge uses the BitVM2 optimistic challenge protocol to trustlessly
//! verify Lumora proof assertions on Bitcoin. Withdrawals are executed via
//! assert transactions; deposits are detected by monitoring Bitcoin UTXOs
//! sent to the bridge address.

use pasta_curves::pallas;

use lumora_contracts::bridge::{
    BridgeError, InboundDeposit, OutboundWithdrawal, RemoteNullifierEpochRoot, RollupBridge,
};
use lumora_contracts::epoch::EpochId;

use crate::config::BitvmConfig;
use crate::protocol::{Assertion, AssertionId, AssertionState, ProtocolManager};
use crate::trace::sha256;
use crate::transactions::XOnlyPubKey;

// ---------------------------------------------------------------------------
// Bridge state
// ---------------------------------------------------------------------------

/// State of a pending withdrawal assertion.
#[derive(Debug)]
struct PendingWithdrawal {
    assertion_id: AssertionId,
    withdrawal: OutboundWithdrawal,
}

/// Bitcoin-backed bridge using BitVM2 for trustless proof verification.
///
/// The bridge operates in two modes:
/// - **Operator mode**: Posts assertions for withdrawal proofs, handles challenges
/// - **Observer mode**: Monitors Bitcoin for deposit UTXOs to the bridge address
///
/// # Withdrawal flow
///
/// 1. `execute_withdrawal()` generates a verification trace for the proof
/// 2. An assertion is registered in the protocol manager
/// 3. The operator posts an Assert TX on Bitcoin (external step)
/// 4. After the timeout, the withdrawal is considered final
///
/// # Deposit flow
///
/// 1. `poll_deposits()` checks for new Bitcoin transactions to the bridge address
/// 2. Each qualifying UTXO is converted to an `InboundDeposit`
pub struct BitvmBridge {
    config: BitvmConfig,
    protocol: ProtocolManager,
    operator_pubkey: XOnlyPubKey,
    pending_withdrawals: Vec<PendingWithdrawal>,
    committed_roots: Vec<pallas::Base>,
    committed_epoch_roots: Vec<(EpochId, pallas::Base)>,
    current_height: u64,
}

impl BitvmBridge {
    /// Create a new BitVM bridge.
    pub fn new(config: BitvmConfig, operator_pubkey: XOnlyPubKey) -> Self {
        let timeout = config.challenge_timeout_blocks;
        Self {
            config,
            protocol: ProtocolManager::new(timeout),
            operator_pubkey,
            pending_withdrawals: Vec::new(),
            committed_roots: Vec::new(),
            committed_epoch_roots: Vec::new(),
            current_height: 0,
        }
    }

    /// Update the current Bitcoin block height.
    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Get the number of active (unfinalized) assertions.
    pub fn active_assertions(&self) -> usize {
        self.protocol.active_count()
    }

    /// Finalize any assertions whose timeout has elapsed.
    ///
    /// Returns the IDs of newly finalized assertions.
    pub fn finalize_expired(&mut self) -> Vec<AssertionId> {
        self.protocol.finalize_expired(self.current_height)
    }

    /// Get configuration.
    pub fn config(&self) -> &BitvmConfig {
        &self.config
    }

    /// Check if a withdrawal assertion has been finalized.
    pub fn is_withdrawal_finalized(&self, assertion_id: &AssertionId) -> bool {
        matches!(
            self.protocol.get_state(assertion_id),
            Some(AssertionState::Finalized)
        )
    }
}

impl RollupBridge for BitvmBridge {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        // In a full implementation, this would query Bitcoin for UTXOs
        // sent to the bridge's Taproot address with OP_RETURN metadata
        // containing the Lumora note commitment.
        //
        // For now, return empty — deposits require an external Bitcoin
        // RPC connection which is handled by the operator daemon.
        Ok(vec![])
    }

    fn execute_withdrawal(
        &self,
        withdrawal: &OutboundWithdrawal,
    ) -> Result<Vec<u8>, BridgeError> {
        // Validate basic parameters
        if withdrawal.amount == 0 {
            return Err(BridgeError::WithdrawFailed(
                "zero-amount withdrawal".into(),
            ));
        }
        if withdrawal.proof_bytes.is_empty() {
            return Err(BridgeError::WithdrawFailed(
                "empty proof bytes".into(),
            ));
        }

        // Check active assertion limit
        if self.protocol.active_count() >= self.config.max_pending_assertions {
            return Err(BridgeError::WithdrawFailed(
                "max pending assertions reached".into(),
            ));
        }

        // In a full implementation, this would:
        // 1. Generate a verification trace for the withdrawal proof
        // 2. Build and broadcast the Assert TX on Bitcoin
        // 3. Return the Assert TX ID
        //
        // The assertion is tracked by the protocol manager. After the
        // timeout period, the withdrawal is finalized and the operator
        // can reclaim the bond via the Timeout TX.

        // Return a deterministic "tx_id" based on the withdrawal data
        let tx_id = sha256(
            &[
                withdrawal.proof_bytes.as_slice(),
                &withdrawal.amount.to_le_bytes(),
                &withdrawal.recipient,
            ]
            .concat(),
        );

        Ok(tx_id.to_vec())
    }

    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError> {
        // In a full implementation, this would embed the Lumora Merkle root
        // in a Bitcoin OP_RETURN output, providing data availability on L1.
        //
        // The root could be committed as part of the Assert TX or in a
        // separate commitment transaction.
        let _ = root;
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: EpochId,
        root: pallas::Base,
    ) -> Result<(), BridgeError> {
        // In a full implementation, this would embed the epoch root in
        // a Bitcoin OP_RETURN output for cross-chain nullifier sync.
        let _ = (epoch_id, root);
        Ok(())
    }

    fn fetch_remote_nullifier_roots(
        &self,
    ) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        // In a full implementation, this would scan Bitcoin for OP_RETURN
        // outputs containing epoch roots from other Lumora instances.
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// Mutable operations (require &mut self, outside the trait)
// ---------------------------------------------------------------------------

impl BitvmBridge {
    /// Register an assertion for a withdrawal (mutable version).
    ///
    /// This is called by the operator daemon after generating the trace
    /// and building the Assert TX.
    pub fn register_withdrawal_assertion(
        &mut self,
        withdrawal: OutboundWithdrawal,
        assertion: Assertion,
    ) -> Result<AssertionId, BridgeError> {
        let id = assertion.id;
        self.protocol
            .register_assertion(assertion)
            .map_err(|e| BridgeError::CommitFailed(e.to_string()))?;

        self.pending_withdrawals.push(PendingWithdrawal {
            assertion_id: id,
            withdrawal,
        });

        Ok(id)
    }

    /// Track a committed state root.
    pub fn record_committed_root(&mut self, root: pallas::Base) {
        self.committed_roots.push(root);
    }

    /// Track a committed epoch root.
    pub fn record_committed_epoch_root(&mut self, epoch_id: EpochId, root: pallas::Base) {
        self.committed_epoch_roots.push((epoch_id, root));
    }

    /// Get the list of committed state roots.
    pub fn committed_roots(&self) -> &[pallas::Base] {
        &self.committed_roots
    }

    /// Get the count of pending withdrawals.
    pub fn pending_withdrawal_count(&self) -> usize {
        self.pending_withdrawals.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BitvmConfig;
    use crate::protocol::Assertion;
    use crate::trace::{
        compute_trace_merkle_root, sha256, step_leaf_hash, StepKind, TraceStep,
        VerificationTrace,
    };

    fn test_bridge() -> BitvmBridge {
        let config = BitvmConfig::default();
        let operator = XOnlyPubKey([0xAA; 32]);
        BitvmBridge::new(config, operator)
    }

    fn test_withdrawal() -> OutboundWithdrawal {
        OutboundWithdrawal {
            amount: 100_000,
            recipient: [0xBB; 32],
            proof_bytes: vec![0xFF; 512],
            nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
        }
    }

    fn dummy_assertion(height: u64) -> Assertion {
        let steps = vec![TraceStep {
            index: 0,
            kind: StepKind::FinalCheck,
            input_hash: [0u8; 32],
            output_hash: [1u8; 32],
            witness: vec![],
        }];
        let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
        let trace = VerificationTrace {
            steps,
            trace_root: compute_trace_merkle_root(&leaves),
            proof_hash: sha256(b"proof"),
            public_inputs_hash: sha256(b"pi"),
            verification_result: true,
        };
        Assertion::from_trace(&trace, height, 10_000_000)
    }

    #[test]
    fn test_bridge_creation() {
        let bridge = test_bridge();
        assert_eq!(bridge.active_assertions(), 0);
        assert_eq!(bridge.pending_withdrawal_count(), 0);
    }

    #[test]
    fn test_poll_deposits_empty() {
        let bridge = test_bridge();
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn test_execute_withdrawal_returns_txid() {
        let bridge = test_bridge();
        let wd = test_withdrawal();
        let tx_id = bridge.execute_withdrawal(&wd).unwrap();
        assert_eq!(tx_id.len(), 32);
    }

    #[test]
    fn test_execute_withdrawal_rejects_zero_amount() {
        let bridge = test_bridge();
        let mut wd = test_withdrawal();
        wd.amount = 0;
        assert!(bridge.execute_withdrawal(&wd).is_err());
    }

    #[test]
    fn test_execute_withdrawal_rejects_empty_proof() {
        let bridge = test_bridge();
        let mut wd = test_withdrawal();
        wd.proof_bytes = vec![];
        assert!(bridge.execute_withdrawal(&wd).is_err());
    }

    #[test]
    fn test_commit_state_root() {
        let bridge = test_bridge();
        assert!(bridge.commit_state_root(pallas::Base::from(42u64)).is_ok());
    }

    #[test]
    fn test_register_withdrawal_assertion() {
        let mut bridge = test_bridge();
        bridge.set_height(100);

        let wd = test_withdrawal();
        let assertion = dummy_assertion(100);
        let id = bridge
            .register_withdrawal_assertion(wd, assertion)
            .unwrap();

        assert_eq!(bridge.active_assertions(), 1);
        assert_eq!(bridge.pending_withdrawal_count(), 1);
        assert!(!bridge.is_withdrawal_finalized(&id));
    }

    #[test]
    fn test_finalize_after_timeout() {
        let mut bridge = test_bridge();
        bridge.set_height(100);

        let wd = test_withdrawal();
        let assertion = dummy_assertion(100);
        let id = bridge
            .register_withdrawal_assertion(wd, assertion)
            .unwrap();

        // Before timeout
        bridge.set_height(200);
        let finalized = bridge.finalize_expired();
        assert!(finalized.is_empty());

        // After timeout (100 + 144 = 244)
        bridge.set_height(244);
        let finalized = bridge.finalize_expired();
        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0], id);
        assert!(bridge.is_withdrawal_finalized(&id));
    }

    #[test]
    fn test_record_committed_root() {
        let mut bridge = test_bridge();
        assert!(bridge.committed_roots().is_empty());

        bridge.record_committed_root(pallas::Base::from(1u64));
        bridge.record_committed_root(pallas::Base::from(2u64));
        assert_eq!(bridge.committed_roots().len(), 2);
    }

    #[test]
    fn test_fetch_remote_roots_empty() {
        let bridge = test_bridge();
        let roots = bridge.fetch_remote_nullifier_roots().unwrap();
        assert!(roots.is_empty());
    }
}
