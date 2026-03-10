//! Rollup integration trait — abstraction boundary between Lumora and the host chain.
//!
//! Implementors of [`RollupBridge`] connect the Lumora privacy pool to a
//! specific rollup (e.g. Strata / Alpen Labs). The trait defines the
//! operations that the host chain must support for Lumora to function.
//!
//! ## Cross-chain nullifier sync (inspired by ZASEON CDNA)
//!
//! The bridge also supports epoch-based nullifier Root synchronization across
//! chains. Each epoch's nullifier Merkle root can be committed to the host
//! chain and fetched from remote chains, enabling cross-chain double-spend
//! prevention without sharing individual nullifiers.

use pasta_curves::pallas;

use crate::epoch::EpochId;

/// Errors from the rollup bridge.
#[derive(Debug)]
pub enum BridgeError {
    /// The deposit was rejected by the host chain.
    DepositRejected(String),
    /// The withdrawal could not be executed on the host chain.
    WithdrawFailed(String),
    /// State commitment submission failed.
    CommitFailed(String),
    /// Communication with the host chain failed.
    ConnectionError(String),
    /// Proof verification encountered an unexpected error.
    VerificationFailed(String),
    /// Nullifier sync failed.
    NullifierSyncFailed(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DepositRejected(msg) => write!(f, "deposit rejected: {msg}"),
            Self::WithdrawFailed(msg) => write!(f, "withdraw failed: {msg}"),
            Self::CommitFailed(msg) => write!(f, "commit failed: {msg}"),
            Self::ConnectionError(msg) => write!(f, "connection error: {msg}"),
            Self::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            Self::NullifierSyncFailed(msg) => write!(f, "nullifier sync failed: {msg}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// A deposit event from the host chain that should be processed by Lumora.
#[derive(Debug, Clone)]
pub struct InboundDeposit {
    /// The note commitment to insert into the tree.
    pub commitment: pallas::Base,
    /// The deposited amount (in base units).
    pub amount: u64,
    /// Host chain transaction identifier (opaque bytes).
    pub tx_id: Vec<u8>,
}

/// A withdrawal request that Lumora has verified and wants to execute on the host chain.
#[derive(Debug, Clone)]
pub struct OutboundWithdrawal {
    /// Amount to unshield.
    pub amount: u64,
    /// Recipient address on the host chain.
    pub recipient: [u8; 32],
    /// The verified proof bytes (for the host chain to optionally re-verify).
    pub proof_bytes: Vec<u8>,
    /// Nullifiers revealed by this withdrawal.
    pub nullifiers: [pallas::Base; 2],
}

/// A nullifier epoch root received from a remote chain.
#[derive(Debug, Clone)]
pub struct RemoteNullifierEpochRoot {
    /// The remote chain's identifier.
    pub chain_id: u64,
    /// Epoch identifier on the remote chain.
    pub epoch_id: EpochId,
    /// Merkle root over nullifiers in that epoch.
    pub root: pallas::Base,
}

/// Trait for connecting Lumora to a host rollup chain.
///
/// The rollup bridge handles:
/// 1. Listening for deposit events from the host chain
/// 2. Executing verified withdrawals on the host chain
/// 3. Committing Lumora state roots to the host chain for data availability
/// 4. Cross-chain nullifier epoch root sync
///
/// # Example (Mock)
///
/// ```rust,ignore
/// struct MockBridge;
///
/// impl RollupBridge for MockBridge {
///     fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
///         Ok(vec![]) // no new deposits
///     }
///     fn execute_withdrawal(&self, _wd: &OutboundWithdrawal) -> Result<Vec<u8>, BridgeError> {
///         Ok(vec![0xAB; 32]) // mock tx id
///     }
///     fn commit_state_root(&self, _root: pallas::Base) -> Result<(), BridgeError> {
///         Ok(())
///     }
///     fn commit_nullifier_epoch_root(&self, _epoch: EpochId, _root: pallas::Base) -> Result<(), BridgeError> {
///         Ok(())
///     }
///     fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
///         Ok(vec![])
///     }
/// }
/// ```
pub trait RollupBridge {
    /// Poll the host chain for new deposit events.
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError>;

    /// Execute a verified withdrawal on the host chain.
    fn execute_withdrawal(&self, withdrawal: &OutboundWithdrawal) -> Result<Vec<u8>, BridgeError>;

    /// Commit the current Lumora Merkle root to the host chain.
    fn commit_state_root(&self, root: pallas::Base) -> Result<(), BridgeError>;

    /// Commit a finalized nullifier epoch root to the host chain.
    ///
    /// This allows other chains to verify that a nullifier has been consumed
    /// on this chain by checking inclusion in the published epoch root.
    fn commit_nullifier_epoch_root(
        &self,
        epoch_id: EpochId,
        root: pallas::Base,
    ) -> Result<(), BridgeError>;

    /// Fetch nullifier epoch roots published by remote chains.
    ///
    /// Returns epoch roots from other chains that should be verified against
    /// cross-domain nullifier proofs.
    fn fetch_remote_nullifier_roots(
        &self,
    ) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError>;
}

/// A no-op bridge for local/standalone operation (no host chain).
pub struct LocalBridge;

impl RollupBridge for LocalBridge {
    fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
        Ok(vec![])
    }

    fn execute_withdrawal(&self, _withdrawal: &OutboundWithdrawal) -> Result<Vec<u8>, BridgeError> {
        Ok(vec![])
    }

    fn commit_state_root(&self, _root: pallas::Base) -> Result<(), BridgeError> {
        Ok(())
    }

    fn commit_nullifier_epoch_root(
        &self,
        _epoch_id: EpochId,
        _root: pallas::Base,
    ) -> Result<(), BridgeError> {
        Ok(())
    }

    fn fetch_remote_nullifier_roots(
        &self,
    ) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::pallas;

    // ── LocalBridge tests ───────────────────────────────────────────

    #[test]
    fn local_bridge_poll_deposits_empty() {
        let bridge = LocalBridge;
        let deposits = bridge.poll_deposits().unwrap();
        assert!(deposits.is_empty());
    }

    #[test]
    fn local_bridge_execute_withdrawal_succeeds() {
        let bridge = LocalBridge;
        let wd = OutboundWithdrawal {
            amount: 100,
            recipient: [0xAA; 32],
            proof_bytes: vec![1, 2, 3],
            nullifiers: [pallas::Base::from(1u64), pallas::Base::from(2u64)],
        };
        let tx_id = bridge.execute_withdrawal(&wd).unwrap();
        assert!(tx_id.is_empty());
    }

    #[test]
    fn local_bridge_commit_state_root_succeeds() {
        let bridge = LocalBridge;
        bridge.commit_state_root(pallas::Base::from(42u64)).unwrap();
    }

    #[test]
    fn local_bridge_commit_nullifier_epoch_root_succeeds() {
        let bridge = LocalBridge;
        bridge
            .commit_nullifier_epoch_root(0, pallas::Base::from(99u64))
            .unwrap();
    }

    #[test]
    fn local_bridge_fetch_remote_nullifier_roots_empty() {
        let bridge = LocalBridge;
        let roots = bridge.fetch_remote_nullifier_roots().unwrap();
        assert!(roots.is_empty());
    }

    // ── BridgeError Display ─────────────────────────────────────────

    #[test]
    fn bridge_error_display() {
        let cases = vec![
            (BridgeError::DepositRejected("bad".into()), "deposit rejected: bad"),
            (BridgeError::WithdrawFailed("no".into()), "withdraw failed: no"),
            (BridgeError::CommitFailed("err".into()), "commit failed: err"),
            (BridgeError::ConnectionError("timeout".into()), "connection error: timeout"),
            (BridgeError::VerificationFailed("oops".into()), "verification failed: oops"),
            (BridgeError::NullifierSyncFailed("fail".into()), "nullifier sync failed: fail"),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
    }

    // ── Mock bridge ─────────────────────────────────────────────────

    struct FailingBridge;

    impl RollupBridge for FailingBridge {
        fn poll_deposits(&self) -> Result<Vec<InboundDeposit>, BridgeError> {
            Err(BridgeError::ConnectionError("offline".into()))
        }
        fn execute_withdrawal(&self, _: &OutboundWithdrawal) -> Result<Vec<u8>, BridgeError> {
            Err(BridgeError::WithdrawFailed("not supported".into()))
        }
        fn commit_state_root(&self, _: pallas::Base) -> Result<(), BridgeError> {
            Err(BridgeError::CommitFailed("unavailable".into()))
        }
        fn commit_nullifier_epoch_root(&self, _: EpochId, _: pallas::Base) -> Result<(), BridgeError> {
            Err(BridgeError::NullifierSyncFailed("no chain".into()))
        }
        fn fetch_remote_nullifier_roots(&self) -> Result<Vec<RemoteNullifierEpochRoot>, BridgeError> {
            Err(BridgeError::ConnectionError("unreachable".into()))
        }
    }

    #[test]
    fn failing_bridge_returns_errors() {
        let bridge = FailingBridge;
        assert!(bridge.poll_deposits().is_err());
        let wd = OutboundWithdrawal {
            amount: 50,
            recipient: [0; 32],
            proof_bytes: vec![],
            nullifiers: [pallas::Base::zero(), pallas::Base::zero()],
        };
        assert!(bridge.execute_withdrawal(&wd).is_err());
        assert!(bridge.commit_state_root(pallas::Base::zero()).is_err());
        assert!(bridge.commit_nullifier_epoch_root(1, pallas::Base::zero()).is_err());
        assert!(bridge.fetch_remote_nullifier_roots().is_err());
    }
}
