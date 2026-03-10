//! Protocol upgrade governance — formal process for managing protocol changes.
//!
//! Provides a structured mechanism for proposing, approving, and activating
//! protocol upgrades (circuit version transitions, parameter changes, etc.).
//!
//! # Upgrade Lifecycle
//!
//! ```text
//! Proposed → Approved → Scheduled → Activated │
//!     │          │                             ├→ Completed
//!     └→ Rejected └→ Cancelled                └→ Expired
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Unique identifier for an upgrade proposal.
pub type ProposalId = String;

/// State of an upgrade proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    /// Proposal has been submitted but not yet approved or rejected.
    Proposed,
    /// Proposal has been approved by governance (e.g., operator, multisig).
    Approved,
    /// Proposal is scheduled for activation at a specific height.
    Scheduled { activation_height: u64 },
    /// Proposal is active — the upgrade has been applied.
    Activated,
    /// Proposal completed successfully (post-activation validation passed).
    Completed,
    /// Proposal was rejected before activation.
    Rejected { reason: String },
    /// Proposal was cancelled after approval but before activation.
    Cancelled,
    /// Proposal expired without being activated.
    Expired,
}

impl std::fmt::Display for ProposalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proposed => write!(f, "proposed"),
            Self::Approved => write!(f, "approved"),
            Self::Scheduled { activation_height } => {
                write!(f, "scheduled (height {})", activation_height)
            }
            Self::Activated => write!(f, "activated"),
            Self::Completed => write!(f, "completed"),
            Self::Rejected { reason } => write!(f, "rejected: {}", reason),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Type of protocol change being proposed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpgradeType {
    /// Circuit version transition (e.g., V1 → V2).
    CircuitUpgrade {
        from_version: String,
        to_version: String,
    },
    /// Parameter change (fee schedule, tree depth, etc.).
    ParameterChange {
        parameter: String,
        old_value: String,
        new_value: String,
    },
    /// State format migration.
    StateMigration {
        from_format: u32,
        to_format: u32,
    },
    /// Network protocol change.
    NetworkProtocolChange {
        description: String,
    },
}

impl std::fmt::Display for UpgradeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CircuitUpgrade { from_version, to_version } => {
                write!(f, "circuit {} → {}", from_version, to_version)
            }
            Self::ParameterChange { parameter, new_value, .. } => {
                write!(f, "param {} = {}", parameter, new_value)
            }
            Self::StateMigration { from_format, to_format } => {
                write!(f, "state format v{} → v{}", from_format, to_format)
            }
            Self::NetworkProtocolChange { description } => {
                write!(f, "network: {}", description)
            }
        }
    }
}

/// A protocol upgrade proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeProposal {
    /// Unique identifier.
    pub id: ProposalId,
    /// Human-readable title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Type of upgrade.
    pub upgrade_type: UpgradeType,
    /// Current state.
    pub state: ProposalState,
    /// Pool height when the proposal was created.
    pub proposed_at_height: u64,
    /// Who proposed it (operator ID or address).
    pub proposer: String,
    /// Optional expiry: if not activated by this height, it expires.
    pub expiry_height: Option<u64>,
}

/// The governance registry — tracks all upgrade proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRegistry {
    proposals: HashMap<ProposalId, UpgradeProposal>,
    /// Sequential counter for generating proposal IDs.
    next_id: u64,
}

impl GovernanceRegistry {
    /// Create a new empty governance registry.
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            next_id: 1,
        }
    }

    /// Submit a new upgrade proposal.
    ///
    /// Returns the proposal ID.
    pub fn propose(
        &mut self,
        title: String,
        description: String,
        upgrade_type: UpgradeType,
        proposer: String,
        current_height: u64,
        expiry_height: Option<u64>,
    ) -> ProposalId {
        let id = format!("PROP-{:04}", self.next_id);
        self.next_id += 1;

        let proposal = UpgradeProposal {
            id: id.clone(),
            title,
            description,
            upgrade_type,
            state: ProposalState::Proposed,
            proposed_at_height: current_height,
            proposer,
            expiry_height,
        };

        self.proposals.insert(id.clone(), proposal);
        id
    }

    /// Approve a proposal (must be in `Proposed` state).
    pub fn approve(&mut self, id: &str) -> Result<(), GovernanceError> {
        let proposal = self.get_mut(id)?;
        if proposal.state != ProposalState::Proposed {
            return Err(GovernanceError::InvalidTransition {
                from: proposal.state.to_string(),
                to: "approved".into(),
            });
        }
        proposal.state = ProposalState::Approved;
        Ok(())
    }

    /// Reject a proposal (must be in `Proposed` state).
    pub fn reject(&mut self, id: &str, reason: String) -> Result<(), GovernanceError> {
        let proposal = self.get_mut(id)?;
        if proposal.state != ProposalState::Proposed {
            return Err(GovernanceError::InvalidTransition {
                from: proposal.state.to_string(),
                to: "rejected".into(),
            });
        }
        proposal.state = ProposalState::Rejected { reason };
        Ok(())
    }

    /// Schedule an approved proposal for activation at a specific height.
    pub fn schedule(
        &mut self,
        id: &str,
        activation_height: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self.get_mut(id)?;
        if proposal.state != ProposalState::Approved {
            return Err(GovernanceError::InvalidTransition {
                from: proposal.state.to_string(),
                to: "scheduled".into(),
            });
        }
        proposal.state = ProposalState::Scheduled { activation_height };
        Ok(())
    }

    /// Cancel a proposal (must be in `Approved` or `Scheduled` state).
    pub fn cancel(&mut self, id: &str) -> Result<(), GovernanceError> {
        let proposal = self.get_mut(id)?;
        match &proposal.state {
            ProposalState::Approved | ProposalState::Scheduled { .. } => {
                proposal.state = ProposalState::Cancelled;
                Ok(())
            }
            _ => Err(GovernanceError::InvalidTransition {
                from: proposal.state.to_string(),
                to: "cancelled".into(),
            }),
        }
    }

    /// Check for proposals that should be activated at the current height.
    ///
    /// Returns IDs of proposals ready for activation.
    pub fn proposals_due(&self, current_height: u64) -> Vec<ProposalId> {
        self.proposals
            .values()
            .filter(|p| {
                matches!(&p.state, ProposalState::Scheduled { activation_height }
                    if *activation_height <= current_height)
            })
            .map(|p| p.id.clone())
            .collect()
    }

    /// Mark a proposal as activated.
    pub fn activate(&mut self, id: &str) -> Result<(), GovernanceError> {
        let proposal = self.get_mut(id)?;
        if !matches!(&proposal.state, ProposalState::Scheduled { .. }) {
            return Err(GovernanceError::InvalidTransition {
                from: proposal.state.to_string(),
                to: "activated".into(),
            });
        }
        proposal.state = ProposalState::Activated;
        Ok(())
    }

    /// Mark a proposal as completed (post-activation).
    pub fn complete(&mut self, id: &str) -> Result<(), GovernanceError> {
        let proposal = self.get_mut(id)?;
        if proposal.state != ProposalState::Activated {
            return Err(GovernanceError::InvalidTransition {
                from: proposal.state.to_string(),
                to: "completed".into(),
            });
        }
        proposal.state = ProposalState::Completed;
        Ok(())
    }

    /// Expire proposals that have passed their expiry height.
    ///
    /// Returns how many proposals were expired.
    pub fn expire_stale(&mut self, current_height: u64) -> usize {
        let expired_ids: Vec<ProposalId> = self
            .proposals
            .values()
            .filter(|p| {
                matches!(
                    &p.state,
                    ProposalState::Proposed | ProposalState::Approved
                ) && p.expiry_height.is_some_and(|h| current_height > h)
            })
            .map(|p| p.id.clone())
            .collect();

        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(p) = self.proposals.get_mut(id) {
                p.state = ProposalState::Expired;
            }
        }
        count
    }

    /// Get a proposal by ID.
    pub fn get(&self, id: &str) -> Option<&UpgradeProposal> {
        self.proposals.get(id)
    }

    /// List all proposals.
    pub fn all_proposals(&self) -> Vec<&UpgradeProposal> {
        self.proposals.values().collect()
    }

    /// List proposals filtered by state.
    pub fn proposals_by_state(&self, state_match: &ProposalState) -> Vec<&UpgradeProposal> {
        self.proposals
            .values()
            .filter(|p| &p.state == state_match)
            .collect()
    }

    /// Number of proposals.
    pub fn count(&self) -> usize {
        self.proposals.len()
    }

    fn get_mut(&mut self, id: &str) -> Result<&mut UpgradeProposal, GovernanceError> {
        self.proposals
            .get_mut(id)
            .ok_or_else(|| GovernanceError::NotFound(id.to_string()))
    }
}

impl Default for GovernanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Governance errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    /// Proposal not found.
    NotFound(ProposalId),
    /// Invalid state transition.
    InvalidTransition { from: String, to: String },
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "proposal not found: {}", id),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {} → {}", from, to)
            }
        }
    }
}

impl std::error::Error for GovernanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle() {
        let mut gov = GovernanceRegistry::new();

        let id = gov.propose(
            "Circuit V2".into(),
            "Upgrade to V2 circuit with fee support".into(),
            UpgradeType::CircuitUpgrade {
                from_version: "V1".into(),
                to_version: "V2".into(),
            },
            "operator-1".into(),
            100,
            Some(200),
        );

        assert_eq!(gov.get(&id).unwrap().state, ProposalState::Proposed);

        gov.approve(&id).unwrap();
        assert_eq!(gov.get(&id).unwrap().state, ProposalState::Approved);

        gov.schedule(&id, 150).unwrap();
        assert!(matches!(
            gov.get(&id).unwrap().state,
            ProposalState::Scheduled { activation_height: 150 }
        ));

        // Not due yet.
        assert!(gov.proposals_due(149).is_empty());
        // Due now.
        assert_eq!(gov.proposals_due(150).len(), 1);

        gov.activate(&id).unwrap();
        assert_eq!(gov.get(&id).unwrap().state, ProposalState::Activated);

        gov.complete(&id).unwrap();
        assert_eq!(gov.get(&id).unwrap().state, ProposalState::Completed);
    }

    #[test]
    fn reject_proposal() {
        let mut gov = GovernanceRegistry::new();
        let id = gov.propose(
            "Bad change".into(),
            "desc".into(),
            UpgradeType::ParameterChange {
                parameter: "fee".into(),
                old_value: "10".into(),
                new_value: "1000".into(),
            },
            "operator-1".into(),
            50,
            None,
        );

        gov.reject(&id, "Too aggressive".into()).unwrap();
        assert!(matches!(
            &gov.get(&id).unwrap().state,
            ProposalState::Rejected { reason } if reason == "Too aggressive"
        ));
    }

    #[test]
    fn cancel_scheduled() {
        let mut gov = GovernanceRegistry::new();
        let id = gov.propose("test".into(), "d".into(),
            UpgradeType::NetworkProtocolChange { description: "x".into() },
            "op".into(), 10, None);
        gov.approve(&id).unwrap();
        gov.schedule(&id, 100).unwrap();
        gov.cancel(&id).unwrap();
        assert_eq!(gov.get(&id).unwrap().state, ProposalState::Cancelled);
    }

    #[test]
    fn expire_stale_proposals() {
        let mut gov = GovernanceRegistry::new();
        let id = gov.propose("old".into(), "d".into(),
            UpgradeType::StateMigration { from_format: 1, to_format: 2 },
            "op".into(), 10, Some(50));

        assert_eq!(gov.expire_stale(45), 0);
        assert_eq!(gov.expire_stale(51), 1);
        assert_eq!(gov.get(&id).unwrap().state, ProposalState::Expired);
    }

    #[test]
    fn invalid_transition() {
        let mut gov = GovernanceRegistry::new();
        let id = gov.propose("test".into(), "d".into(),
            UpgradeType::NetworkProtocolChange { description: "x".into() },
            "op".into(), 10, None);

        // Can't schedule without approving first.
        assert!(gov.schedule(&id, 100).is_err());
        // Can't activate from proposed state.
        assert!(gov.activate(&id).is_err());
    }
}
