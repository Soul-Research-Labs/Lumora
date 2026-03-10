//! KYC/AML compliance hooks for deposit and withdrawal validation.
//!
//! Provides a pluggable compliance layer that can reject deposits or
//! withdrawals based on external validation rules (e.g., OFAC screening,
//! identity verification status, jurisdiction checks).
//!
//! # Usage
//!
//! Implement the [`ComplianceOracle`] trait with your compliance provider,
//! then wrap your deposit/withdraw flow with [`validate_deposit`] and
//! [`validate_withdrawal`].

use serde::{Deserialize, Serialize};

/// Result of a compliance check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceVerdict {
    /// Transaction is allowed.
    Approved,
    /// Transaction is blocked, with a reason code.
    Blocked { reason: ComplianceReason },
    /// Compliance check could not be completed (e.g., oracle unreachable).
    /// The caller decides whether to allow or deny.
    Unavailable,
}

/// Machine-readable reason codes for compliance rejections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceReason {
    /// Address is on a sanctions list (e.g., OFAC SDN).
    Sanctioned,
    /// Depositor has not completed KYC verification.
    KycRequired,
    /// Transaction exceeds the per-transaction or daily limit.
    LimitExceeded,
    /// Jurisdiction is restricted.
    RestrictedJurisdiction,
    /// Suspicious activity detected by heuristics.
    SuspiciousActivity,
    /// Custom reason (free-form for provider-specific rules).
    Custom(String),
}

impl std::fmt::Display for ComplianceReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sanctioned => write!(f, "sanctioned address"),
            Self::KycRequired => write!(f, "KYC verification required"),
            Self::LimitExceeded => write!(f, "transaction limit exceeded"),
            Self::RestrictedJurisdiction => write!(f, "restricted jurisdiction"),
            Self::SuspiciousActivity => write!(f, "suspicious activity detected"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Context for a deposit compliance check.
#[derive(Debug, Clone)]
pub struct DepositContext {
    /// The depositor's public identifier (e.g., L1 address as hex).
    pub depositor_id: String,
    /// Amount being deposited (in base units).
    pub amount: u64,
    /// Asset identifier.
    pub asset: u64,
}

/// Context for a withdrawal compliance check.
#[derive(Debug, Clone)]
pub struct WithdrawalContext {
    /// The recipient's public identifier (e.g., L1 address as hex).
    pub recipient_id: String,
    /// Amount being withdrawn (in base units).
    pub amount: u64,
    /// Asset identifier.
    pub asset: u64,
    /// The sender's viewing key hex (if disclosed for compliance).
    pub sender_viewing_key: Option<String>,
}

/// Trait for compliance validation providers.
///
/// Implementations can check against:
/// - On-chain sanctions lists
/// - External KYC providers (Chainalysis, Elliptic, etc.)
/// - Internal risk scoring
/// - Jurisdiction whitelists/blacklists
pub trait ComplianceOracle {
    /// Check whether a deposit should be allowed.
    fn check_deposit(&self, ctx: &DepositContext) -> ComplianceVerdict;

    /// Check whether a withdrawal should be allowed.
    fn check_withdrawal(&self, ctx: &WithdrawalContext) -> ComplianceVerdict;
}

/// A permissive compliance oracle that approves everything.
///
/// Use as the default when no compliance checks are configured.
pub struct PermissiveOracle;

impl ComplianceOracle for PermissiveOracle {
    fn check_deposit(&self, _ctx: &DepositContext) -> ComplianceVerdict {
        ComplianceVerdict::Approved
    }

    fn check_withdrawal(&self, _ctx: &WithdrawalContext) -> ComplianceVerdict {
        ComplianceVerdict::Approved
    }
}

/// A threshold-based oracle that blocks transactions above a limit.
///
/// Useful as a simple compliance layer or for testing.
pub struct ThresholdOracle {
    /// Maximum allowed deposit amount.
    pub max_deposit: u64,
    /// Maximum allowed withdrawal amount.
    pub max_withdrawal: u64,
}

impl ComplianceOracle for ThresholdOracle {
    fn check_deposit(&self, ctx: &DepositContext) -> ComplianceVerdict {
        if ctx.amount > self.max_deposit {
            ComplianceVerdict::Blocked {
                reason: ComplianceReason::LimitExceeded,
            }
        } else {
            ComplianceVerdict::Approved
        }
    }

    fn check_withdrawal(&self, ctx: &WithdrawalContext) -> ComplianceVerdict {
        if ctx.amount > self.max_withdrawal {
            ComplianceVerdict::Blocked {
                reason: ComplianceReason::LimitExceeded,
            }
        } else {
            ComplianceVerdict::Approved
        }
    }
}

/// Validate a deposit against a compliance oracle.
///
/// Returns `Ok(())` if approved, or `Err(reason)` if blocked.
/// `Unavailable` verdicts are treated as approved (fail-open).
pub fn validate_deposit(
    oracle: &dyn ComplianceOracle,
    ctx: &DepositContext,
) -> Result<(), ComplianceReason> {
    match oracle.check_deposit(ctx) {
        ComplianceVerdict::Approved | ComplianceVerdict::Unavailable => Ok(()),
        ComplianceVerdict::Blocked { reason } => Err(reason),
    }
}

/// Validate a withdrawal against a compliance oracle.
///
/// Returns `Ok(())` if approved, or `Err(reason)` if blocked.
/// `Unavailable` verdicts are treated as approved (fail-open).
pub fn validate_withdrawal(
    oracle: &dyn ComplianceOracle,
    ctx: &WithdrawalContext,
) -> Result<(), ComplianceReason> {
    match oracle.check_withdrawal(ctx) {
        ComplianceVerdict::Approved | ComplianceVerdict::Unavailable => Ok(()),
        ComplianceVerdict::Blocked { reason } => Err(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_oracle_approves_all() {
        let oracle = PermissiveOracle;
        let deposit_ctx = DepositContext {
            depositor_id: "0xabc".into(),
            amount: 1_000_000,
            asset: 0,
        };
        assert_eq!(oracle.check_deposit(&deposit_ctx), ComplianceVerdict::Approved);

        let withdraw_ctx = WithdrawalContext {
            recipient_id: "0xdef".into(),
            amount: 500_000,
            asset: 0,
            sender_viewing_key: None,
        };
        assert_eq!(oracle.check_withdrawal(&withdraw_ctx), ComplianceVerdict::Approved);
    }

    #[test]
    fn threshold_oracle_blocks_large_deposits() {
        let oracle = ThresholdOracle {
            max_deposit: 10_000,
            max_withdrawal: 10_000,
        };

        let small = DepositContext {
            depositor_id: "0xabc".into(),
            amount: 5_000,
            asset: 0,
        };
        assert_eq!(oracle.check_deposit(&small), ComplianceVerdict::Approved);

        let large = DepositContext {
            depositor_id: "0xabc".into(),
            amount: 50_000,
            asset: 0,
        };
        assert!(matches!(
            oracle.check_deposit(&large),
            ComplianceVerdict::Blocked { reason: ComplianceReason::LimitExceeded }
        ));
    }

    #[test]
    fn validate_helpers() {
        let oracle = ThresholdOracle {
            max_deposit: 1_000,
            max_withdrawal: 1_000,
        };
        let ctx = DepositContext {
            depositor_id: "user1".into(),
            amount: 500,
            asset: 0,
        };
        assert!(validate_deposit(&oracle, &ctx).is_ok());

        let ctx_big = DepositContext {
            depositor_id: "user1".into(),
            amount: 5_000,
            asset: 0,
        };
        assert_eq!(
            validate_deposit(&oracle, &ctx_big).unwrap_err(),
            ComplianceReason::LimitExceeded,
        );
    }

    #[test]
    fn threshold_oracle_blocks_large_withdrawals() {
        let oracle = ThresholdOracle {
            max_deposit: 10_000,
            max_withdrawal: 5_000,
        };
        let small = WithdrawalContext {
            recipient_id: "0xdef".into(),
            amount: 3_000,
            asset: 0,
            sender_viewing_key: None,
        };
        assert_eq!(oracle.check_withdrawal(&small), ComplianceVerdict::Approved);

        let large = WithdrawalContext {
            recipient_id: "0xdef".into(),
            amount: 10_000,
            asset: 0,
            sender_viewing_key: None,
        };
        assert!(matches!(
            oracle.check_withdrawal(&large),
            ComplianceVerdict::Blocked { reason: ComplianceReason::LimitExceeded }
        ));
    }

    #[test]
    fn validate_withdrawal_helper() {
        let oracle = ThresholdOracle {
            max_deposit: 1_000,
            max_withdrawal: 2_000,
        };
        let ctx = WithdrawalContext {
            recipient_id: "user2".into(),
            amount: 1_500,
            asset: 0,
            sender_viewing_key: Some("0xviewkey".into()),
        };
        assert!(validate_withdrawal(&oracle, &ctx).is_ok());

        let ctx_big = WithdrawalContext {
            recipient_id: "user2".into(),
            amount: 5_000,
            asset: 0,
            sender_viewing_key: None,
        };
        assert_eq!(
            validate_withdrawal(&oracle, &ctx_big).unwrap_err(),
            ComplianceReason::LimitExceeded,
        );
    }

    /// Custom oracle that always returns Unavailable.
    struct UnavailableOracle;
    impl ComplianceOracle for UnavailableOracle {
        fn check_deposit(&self, _: &DepositContext) -> ComplianceVerdict {
            ComplianceVerdict::Unavailable
        }
        fn check_withdrawal(&self, _: &WithdrawalContext) -> ComplianceVerdict {
            ComplianceVerdict::Unavailable
        }
    }

    #[test]
    fn unavailable_verdict_failopen() {
        let oracle = UnavailableOracle;
        let dep = DepositContext {
            depositor_id: "user".into(),
            amount: 999_999,
            asset: 0,
        };
        assert!(validate_deposit(&oracle, &dep).is_ok());

        let wd = WithdrawalContext {
            recipient_id: "user".into(),
            amount: 999_999,
            asset: 0,
            sender_viewing_key: None,
        };
        assert!(validate_withdrawal(&oracle, &wd).is_ok());
    }

    #[test]
    fn compliance_reason_display() {
        assert_eq!(ComplianceReason::Sanctioned.to_string(), "sanctioned address");
        assert_eq!(ComplianceReason::KycRequired.to_string(), "KYC verification required");
        assert_eq!(ComplianceReason::LimitExceeded.to_string(), "transaction limit exceeded");
        assert_eq!(ComplianceReason::RestrictedJurisdiction.to_string(), "restricted jurisdiction");
        assert_eq!(ComplianceReason::SuspiciousActivity.to_string(), "suspicious activity detected");
        assert_eq!(ComplianceReason::Custom("test".into()).to_string(), "test");
    }

    #[test]
    fn threshold_oracle_boundary_values() {
        let oracle = ThresholdOracle {
            max_deposit: 100,
            max_withdrawal: 100,
        };
        // Exactly at the limit → approved.
        let at_limit = DepositContext {
            depositor_id: "user".into(),
            amount: 100,
            asset: 0,
        };
        assert_eq!(oracle.check_deposit(&at_limit), ComplianceVerdict::Approved);

        // One above the limit → blocked.
        let over = DepositContext {
            depositor_id: "user".into(),
            amount: 101,
            asset: 0,
        };
        assert!(matches!(
            oracle.check_deposit(&over),
            ComplianceVerdict::Blocked { .. }
        ));
    }
}
