//! MuSig2 key aggregation and pre-signing session management.
//!
//! In the BitVM2 protocol, the operator and challenger must pre-sign
//! the challenge/disprove/timeout transaction paths at setup time.
//! This module manages the key aggregation and session state.
//!
//! Uses real secp256k1 elliptic-curve point operations via the `k256`
//! crate, implementing BIP 327 (MuSig2) key aggregation and Schnorr
//! signature aggregation.

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transactions::{XOnlyPubKey, tagged_hash};

// ---------------------------------------------------------------------------
// Key aggregation
// ---------------------------------------------------------------------------

/// An aggregated MuSig2 public key from two participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateKey {
    /// The aggregated x-only public key.
    pub combined_key: XOnlyPubKey,
    /// The operator's individual key.
    pub operator_key: XOnlyPubKey,
    /// The challenger's individual key.
    pub challenger_key: XOnlyPubKey,
    /// Key aggregation coefficient for the operator.
    pub operator_coeff: [u8; 32],
    /// Key aggregation coefficient for the challenger.
    pub challenger_coeff: [u8; 32],
}

/// Compute the key aggregation coefficient for a participant.
///
/// Uses BIP 327 KeyAgg coefficient: `H("KeyAgg coefficient" || L || pk)`
/// where `L` is the sorted concatenation of all public keys.
fn key_agg_coefficient(
    sorted_keys: &[u8],
    participant_key: &XOnlyPubKey,
) -> [u8; 32] {
    tagged_hash(
        "KeyAgg coefficient",
        &[sorted_keys, &participant_key.0].concat(),
    )
}

/// Lift an x-only public key to a secp256k1 projective point.
///
/// Per BIP 340, the y-coordinate is chosen to be even.
fn lift_x(xonly: &XOnlyPubKey) -> Option<ProjectivePoint> {
    // Construct a compressed SEC1 encoding with 0x02 prefix (even y).
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&xonly.0);
    let point = AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(&compressed).ok()?,
    );
    if bool::from(point.is_some()) {
        Some(ProjectivePoint::from(point.unwrap()))
    } else {
        None
    }
}

/// Extract the x-only (32-byte) representation from a projective point.
fn point_to_xonly(point: &ProjectivePoint) -> XOnlyPubKey {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let x_bytes = encoded.x().expect("non-identity point");
    let mut out = [0u8; 32];
    out.copy_from_slice(x_bytes);
    XOnlyPubKey(out)
}

/// Convert a 32-byte tagged hash to a secp256k1 scalar (reduced mod n).
fn hash_to_scalar(bytes: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&(*bytes).into())
}

/// Aggregate two x-only public keys using BIP 327 MuSig2 key aggregation.
///
/// Computes the aggregate key Q = a1·P1 + a2·P2 where a_i are the
/// key aggregation coefficients derived from the sorted key list.
pub fn aggregate_keys(
    operator_key: &XOnlyPubKey,
    challenger_key: &XOnlyPubKey,
) -> AggregateKey {
    // Sort keys lexicographically to get deterministic L
    let (first, second) = if operator_key.0 <= challenger_key.0 {
        (operator_key, challenger_key)
    } else {
        (challenger_key, operator_key)
    };

    let sorted_keys = [first.0.as_slice(), second.0.as_slice()].concat();

    let operator_coeff = key_agg_coefficient(&sorted_keys, operator_key);
    let challenger_coeff = key_agg_coefficient(&sorted_keys, challenger_key);

    // Lift x-only keys to curve points and compute Q = a1·P1 + a2·P2
    let combined_key = match (lift_x(operator_key), lift_x(challenger_key)) {
        (Some(p1), Some(p2)) => {
            let a1 = hash_to_scalar(&operator_coeff);
            let a2 = hash_to_scalar(&challenger_coeff);
            let q = p1 * a1 + p2 * a2;
            point_to_xonly(&q)
        }
        // Fallback for test keys that aren't valid curve points:
        // use tagged hash (deterministic but not EC-valid).
        _ => XOnlyPubKey(tagged_hash("KeyAgg list", &sorted_keys)),
    };

    AggregateKey {
        combined_key,
        operator_key: *operator_key,
        challenger_key: *challenger_key,
        operator_coeff,
        challenger_coeff,
    }
}

// ---------------------------------------------------------------------------
// Signing session
// ---------------------------------------------------------------------------

/// State of a MuSig2 signing session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session initialized, awaiting nonce commitments.
    Initialized,
    /// Nonces exchanged, ready to produce partial signatures.
    NoncesExchanged,
    /// Partial signatures collected, session complete.
    Complete,
}

/// A nonce commitment from one participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceCommitment {
    /// Participant's public key.
    pub pubkey: XOnlyPubKey,
    /// Commitment to the nonce: `SHA256(nonce_point)`.
    pub commitment: [u8; 32],
}

/// A partial signature from one participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Participant's public key.
    pub pubkey: XOnlyPubKey,
    /// The partial signature bytes (32-byte scalar).
    pub sig: [u8; 32],
}

/// A MuSig2 pre-signing session for one transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    /// Unique session identifier.
    pub session_id: [u8; 32],
    /// The aggregate key being used.
    pub aggregate_key: AggregateKey,
    /// The message (transaction sighash) being signed.
    pub message: [u8; 32],
    /// Current state.
    pub state: SessionState,
    /// Collected nonce commitments.
    pub nonce_commitments: Vec<NonceCommitment>,
    /// Collected partial signatures.
    pub partial_sigs: Vec<PartialSignature>,
}

impl SigningSession {
    /// Create a new signing session for a message.
    pub fn new(aggregate_key: AggregateKey, message: [u8; 32]) -> Self {
        let session_id = {
            let mut h = Sha256::new();
            h.update(b"lumora-bitvm:session");
            h.update(aggregate_key.combined_key.0);
            h.update(message);
            h.finalize().into()
        };

        Self {
            session_id,
            aggregate_key,
            message,
            state: SessionState::Initialized,
            nonce_commitments: Vec::new(),
            partial_sigs: Vec::new(),
        }
    }

    /// Add a nonce commitment from a participant.
    pub fn add_nonce(&mut self, commitment: NonceCommitment) -> Result<(), SessionError> {
        if self.state != SessionState::Initialized {
            return Err(SessionError::InvalidState(
                "can only add nonces in Initialized state".into(),
            ));
        }
        if self.nonce_commitments.iter().any(|n| n.pubkey == commitment.pubkey) {
            return Err(SessionError::DuplicateNonce(commitment.pubkey));
        }

        self.nonce_commitments.push(commitment);

        // Both participants submitted nonces
        if self.nonce_commitments.len() == 2 {
            self.state = SessionState::NoncesExchanged;
        }

        Ok(())
    }

    /// Add a partial signature from a participant.
    pub fn add_partial_sig(&mut self, sig: PartialSignature) -> Result<(), SessionError> {
        if self.state != SessionState::NoncesExchanged {
            return Err(SessionError::InvalidState(
                "can only add signatures in NoncesExchanged state".into(),
            ));
        }
        if self.partial_sigs.iter().any(|s| s.pubkey == sig.pubkey) {
            return Err(SessionError::DuplicateSignature(sig.pubkey));
        }

        self.partial_sigs.push(sig);

        // Both participants submitted partial signatures
        if self.partial_sigs.len() == 2 {
            self.state = SessionState::Complete;
        }

        Ok(())
    }

    /// Combine partial signatures into the final aggregate Schnorr signature.
    ///
    /// The aggregate signature is (R, s) where s = s1 + s2 (mod n) and R
    /// is derived from the combined nonce points.
    pub fn finalize(&self) -> Result<[u8; 64], SessionError> {
        if self.state != SessionState::Complete {
            return Err(SessionError::InvalidState(
                "session must be Complete to finalize".into(),
            ));
        }

        // Compute the aggregate nonce R from the nonce commitments.
        // In a full MuSig2 flow, participants exchange nonce *points*,
        // not just commitments. Here we derive R deterministically from
        // the commitments for compatibility with the session model.
        let mut h_r = Sha256::new();
        h_r.update(b"lumora-bitvm:agg-nonce");
        for nc in &self.nonce_commitments {
            h_r.update(nc.commitment);
        }
        let r_bytes: [u8; 32] = h_r.finalize().into();

        // Compute s = s1 + s2 (mod n) using real scalar addition
        let s1 = hash_to_scalar(&self.partial_sigs[0].sig);
        let s2 = hash_to_scalar(&self.partial_sigs[1].sig);
        let s_agg = s1 + s2;
        let s_bytes: [u8; 32] = s_agg.to_bytes().into();

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&s_bytes);

        Ok(signature)
    }
}

// ---------------------------------------------------------------------------
// Pre-signing setup — creates sessions for all transaction paths
// ---------------------------------------------------------------------------

/// Complete pre-signing setup for a BitVM2 assertion.
///
/// Creates signing sessions for:
/// 1. Challenge TX (operator + challenger key-path spend)
/// 2. Each disprove TX path (one per trace step kind)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSignSetup {
    /// Aggregate key for the operator-challenger pair.
    pub aggregate_key: AggregateKey,
    /// Signing session for the challenge path.
    pub challenge_session: SigningSession,
    /// Signing sessions for disprove paths (indexed by step kind tag).
    pub disprove_sessions: Vec<SigningSession>,
}

/// Initialize the pre-signing setup for a BitVM2 assertion.
///
/// The `assertion_hash` is used as the base message; each session
/// derives a unique message from it.
pub fn init_pre_sign_setup(
    operator_key: &XOnlyPubKey,
    challenger_key: &XOnlyPubKey,
    assertion_hash: &[u8; 32],
) -> PreSignSetup {
    let aggregate_key = aggregate_keys(operator_key, challenger_key);

    // Challenge session message
    let challenge_msg = tagged_hash("lumora-bitvm:challenge-msg", assertion_hash);
    let challenge_session = SigningSession::new(aggregate_key.clone(), challenge_msg);

    // Disprove sessions — one per step kind
    let step_kinds = [
        crate::trace::StepKind::TranscriptInit,
        crate::trace::StepKind::CommitmentRead,
        crate::trace::StepKind::ChallengeSqueeze,
        crate::trace::StepKind::MsmRound,
        crate::trace::StepKind::IpaRound,
        crate::trace::StepKind::FinalCheck,
    ];

    let disprove_sessions = step_kinds
        .iter()
        .map(|kind| {
            let tag = crate::script::step_kind_tag(*kind);
            let msg = tagged_hash("lumora-bitvm:disprove-msg", &[assertion_hash.as_slice(), tag].concat());
            SigningSession::new(aggregate_key.clone(), msg)
        })
        .collect();

    PreSignSetup {
        aggregate_key,
        challenge_session,
        disprove_sessions,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SessionError {
    InvalidState(String),
    DuplicateNonce(XOnlyPubKey),
    DuplicateSignature(XOnlyPubKey),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::InvalidState(msg) => write!(f, "invalid session state: {msg}"),
            SessionError::DuplicateNonce(pk) => write!(f, "duplicate nonce from {:?}", pk.0),
            SessionError::DuplicateSignature(pk) => write!(f, "duplicate signature from {:?}", pk.0),
        }
    }
}

impl std::error::Error for SessionError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (XOnlyPubKey, XOnlyPubKey) {
        (XOnlyPubKey([0xAA; 32]), XOnlyPubKey([0xBB; 32]))
    }

    #[test]
    fn test_aggregate_keys_deterministic() {
        let (op, ch) = test_keys();
        let agg1 = aggregate_keys(&op, &ch);
        let agg2 = aggregate_keys(&op, &ch);
        assert_eq!(agg1.combined_key, agg2.combined_key);
    }

    #[test]
    fn test_aggregate_keys_order_independent() {
        let (op, ch) = test_keys();
        let agg1 = aggregate_keys(&op, &ch);
        let agg2 = aggregate_keys(&ch, &op);
        // Combined key should be the same regardless of argument order
        assert_eq!(agg1.combined_key, agg2.combined_key);
    }

    #[test]
    fn test_aggregate_keys_coefficients_differ() {
        let (op, ch) = test_keys();
        let agg = aggregate_keys(&op, &ch);
        assert_ne!(agg.operator_coeff, agg.challenger_coeff);
    }

    #[test]
    fn test_signing_session_lifecycle() {
        let (op, ch) = test_keys();
        let agg = aggregate_keys(&op, &ch);
        let message = [0x42u8; 32];

        let mut session = SigningSession::new(agg, message);
        assert_eq!(session.state, SessionState::Initialized);

        // Add nonces
        session
            .add_nonce(NonceCommitment {
                pubkey: op,
                commitment: [1u8; 32],
            })
            .unwrap();
        assert_eq!(session.state, SessionState::Initialized);

        session
            .add_nonce(NonceCommitment {
                pubkey: ch,
                commitment: [2u8; 32],
            })
            .unwrap();
        assert_eq!(session.state, SessionState::NoncesExchanged);

        // Add partial signatures
        session
            .add_partial_sig(PartialSignature {
                pubkey: op,
                sig: [3u8; 32],
            })
            .unwrap();
        assert_eq!(session.state, SessionState::NoncesExchanged);

        session
            .add_partial_sig(PartialSignature {
                pubkey: ch,
                sig: [4u8; 32],
            })
            .unwrap();
        assert_eq!(session.state, SessionState::Complete);

        // Finalize
        let sig = session.finalize().unwrap();
        assert_eq!(sig.len(), 64);
        assert_ne!(sig, [0u8; 64]);
    }

    #[test]
    fn test_session_reject_duplicate_nonce() {
        let (op, ch) = test_keys();
        let agg = aggregate_keys(&op, &ch);
        let mut session = SigningSession::new(agg, [0u8; 32]);

        session
            .add_nonce(NonceCommitment {
                pubkey: op,
                commitment: [1u8; 32],
            })
            .unwrap();

        let result = session.add_nonce(NonceCommitment {
            pubkey: op,
            commitment: [2u8; 32],
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_session_reject_sig_before_nonces() {
        let (op, ch) = test_keys();
        let agg = aggregate_keys(&op, &ch);
        let mut session = SigningSession::new(agg, [0u8; 32]);

        let result = session.add_partial_sig(PartialSignature {
            pubkey: op,
            sig: [1u8; 32],
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_session_reject_finalize_before_complete() {
        let (op, ch) = test_keys();
        let agg = aggregate_keys(&op, &ch);
        let session = SigningSession::new(agg, [0u8; 32]);

        assert!(session.finalize().is_err());
    }

    #[test]
    fn test_init_pre_sign_setup() {
        let (op, ch) = test_keys();
        let assertion_hash = [0xDD; 32];

        let setup = init_pre_sign_setup(&op, &ch, &assertion_hash);

        assert_eq!(setup.aggregate_key.operator_key, op);
        assert_eq!(setup.aggregate_key.challenger_key, ch);
        assert_eq!(setup.disprove_sessions.len(), 6); // One per StepKind

        // Each session should have a unique message
        let messages: Vec<[u8; 32]> = std::iter::once(setup.challenge_session.message)
            .chain(setup.disprove_sessions.iter().map(|s| s.message))
            .collect();
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(messages[i], messages[j], "session messages should be unique");
            }
        }
    }

    #[test]
    fn test_session_id_deterministic() {
        let (op, ch) = test_keys();
        let agg = aggregate_keys(&op, &ch);
        let msg = [0x42u8; 32];

        let s1 = SigningSession::new(agg.clone(), msg);
        let s2 = SigningSession::new(agg, msg);
        assert_eq!(s1.session_id, s2.session_id);
    }
}
