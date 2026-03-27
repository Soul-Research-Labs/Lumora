//! Versioned verifier key set — supports dual-key transition during circuit upgrades.
//!
//! During a circuit version transition, the node needs to verify proofs
//! generated with either the old or new circuit version. This module provides
//! a `VersionedVerifierSet` that maps `CircuitVersion` → verifier parameters
//! and dispatches verification to the correct key.
//!
//! # Transition Protocol
//!
//! 1. **Before upgrade**: Only `V1` keys are loaded.
//! 2. **During transition**: Both `V1` and `V2` keys are loaded.
//!    Proofs tagged with `V1` are verified with the old keys;
//!    proofs tagged with `V2` with the new keys.
//! 3. **After transition**: `V1` keys are removed.
//!    Any `V1`-tagged proofs will be rejected.

use std::collections::HashMap;

use lumora_circuits::CircuitVersion;
use lumora_prover::{VerifierParams, WithdrawVerifierParams};

/// A set of verifier parameters keyed by circuit version.
///
/// Enables verification of proofs from multiple circuit versions during
/// an upgrade transition period. 
pub struct VersionedVerifierSet {
    transfer_keys: HashMap<CircuitVersion, VerifierParams>,
    withdraw_keys: HashMap<CircuitVersion, WithdrawVerifierParams>,
    /// The current (preferred) version for new proofs.
    current_version: CircuitVersion,
    /// Optional deadline height: after this height, only `current_version` proofs are accepted.
    deprecation_height: Option<u64>,
}

impl VersionedVerifierSet {
    /// Create a new set with a single version's keys as the current version.
    pub fn new(
        version: CircuitVersion,
        transfer: VerifierParams,
        withdraw: WithdrawVerifierParams,
    ) -> Self {
        let mut transfer_keys = HashMap::new();
        let mut withdraw_keys = HashMap::new();
        transfer_keys.insert(version, transfer);
        withdraw_keys.insert(version, withdraw);
        Self {
            transfer_keys,
            withdraw_keys,
            current_version: version,
            deprecation_height: None,
        }
    }

    /// Add an additional circuit version's keys (for transition).
    pub fn add_version(
        &mut self,
        version: CircuitVersion,
        transfer: VerifierParams,
        withdraw: WithdrawVerifierParams,
    ) {
        self.transfer_keys.insert(version, transfer);
        self.withdraw_keys.insert(version, withdraw);
    }

    /// Remove a circuit version's keys (end of transition).
    ///
    /// Returns `false` without removing if `version` is the current version.
    pub fn remove_version(&mut self, version: &CircuitVersion) -> bool {
        if *version == self.current_version {
            return false;
        }
        self.transfer_keys.remove(version);
        self.withdraw_keys.remove(version);
        true
    }

    /// Set the current (preferred) version.
    pub fn set_current_version(&mut self, version: CircuitVersion) {
        self.current_version = version;
    }

    /// Set a deprecation height: after this pool height, only `current_version` is accepted.
    pub fn set_deprecation_height(&mut self, height: u64) {
        self.deprecation_height = Some(height);
    }

    /// Clear the deprecation height.
    pub fn clear_deprecation_height(&mut self) {
        self.deprecation_height = None;
    }

    /// Check if a version is accepted at the given pool height.
    pub fn is_version_accepted(&self, version: &CircuitVersion, pool_height: u64) -> bool {
        // After deprecation height, only current version is accepted.
        if let Some(deadline) = self.deprecation_height {
            if pool_height > deadline && *version != self.current_version {
                return false;
            }
        }
        self.transfer_keys.contains_key(version)
    }

    /// Look up transfer verifier params for a given version.
    pub fn transfer_verifier(&self, version: &CircuitVersion) -> Option<&VerifierParams> {
        self.transfer_keys.get(version)
    }

    /// Look up withdraw verifier params for a given version.
    pub fn withdraw_verifier(&self, version: &CircuitVersion) -> Option<&WithdrawVerifierParams> {
        self.withdraw_keys.get(version)
    }

    /// Current version.
    pub fn current_version(&self) -> &CircuitVersion {
        &self.current_version
    }

    /// All loaded versions.
    pub fn loaded_versions(&self) -> Vec<CircuitVersion> {
        self.transfer_keys.keys().cloned().collect()
    }

    /// Whether we're in a dual-key transition (more than one version loaded).
    pub fn is_in_transition(&self) -> bool {
        self.transfer_keys.len() > 1
    }
}

/// Error when a proof targets an unsupported or deprecated circuit version.
#[derive(Debug, Clone)]
pub enum VersionedVerifyError {
    /// The circuit version is not loaded in the verifier set.
    UnsupportedVersion(CircuitVersion),
    /// The circuit version has been deprecated (past the deprecation height).
    DeprecatedVersion {
        version: CircuitVersion,
        deadline: u64,
        current_height: u64,
    },
    /// The proof failed verification against the correct key.
    VerificationFailed,
}

impl std::fmt::Display for VersionedVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported circuit version: {:?}", v),
            Self::DeprecatedVersion { version, deadline, current_height } => {
                write!(
                    f,
                    "circuit version {:?} deprecated at height {} (current: {})",
                    version, deadline, current_height
                )
            }
            Self::VerificationFailed => write!(f, "proof verification failed"),
        }
    }
}

impl std::error::Error for VersionedVerifyError {}

/// Transition state summary for monitoring / status endpoints.
#[derive(Debug, Clone)]
pub struct TransitionStatus {
    /// Currently preferred version.
    pub current_version: CircuitVersion,
    /// All loaded versions.
    pub loaded_versions: Vec<CircuitVersion>,
    /// Whether a transition is in progress.
    pub in_transition: bool,
    /// Optional deprecation height.
    pub deprecation_height: Option<u64>,
}

impl VersionedVerifierSet {
    /// Get the transition status for monitoring.
    pub fn transition_status(&self) -> TransitionStatus {
        TransitionStatus {
            current_version: self.current_version,
            loaded_versions: self.loaded_versions(),
            in_transition: self.is_in_transition(),
            deprecation_height: self.deprecation_height,
        }
    }
}
