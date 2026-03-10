//! Nullifier — the double-spend prevention token.
//!
//! When a note is spent, its nullifier is published on-chain.
//! If the same nullifier appears twice, the transaction is rejected.
//!
//! ## V1 (legacy)
//! `N = PoseidonHash(spending_key_as_field, commitment)`
//!
//! ## V2 (domain-separated, inspired by ZASEON CDNA)
//! `N = PoseidonHash4(spending_key_as_field, commitment, chain_id, app_id)`
//!
//! Domain separation ensures nullifiers are distinct across chains and
//! applications, enabling safe cross-chain privacy without nullifier
//! collisions.

use pasta_curves::pallas;

use lumora_primitives::poseidon;

use crate::commitment::NoteCommitment;
use crate::keys::{scalar_to_base, SpendingKey};

/// Domain parameters that make nullifiers unique across chains and applications.
///
/// Inspired by ZASEON's Cross-Domain Nullifier Algebra (CDNA), this binds
/// nullifiers to a specific (chain, application) pair so the same note
/// cannot be double-spent across different deployments.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NullifierDomain {
    /// Chain identifier (e.g. 1 for mainnet, unique per rollup).
    pub chain_id: u64,
    /// Application identifier (unique per Lumora deployment on a chain).
    pub app_id: u64,
}

impl NullifierDomain {
    pub fn new(chain_id: u64, app_id: u64) -> Self {
        Self { chain_id, app_id }
    }
}

/// Default domain for single-chain / standalone operation.
impl Default for NullifierDomain {
    fn default() -> Self {
        Self { chain_id: 0, app_id: 0 }
    }
}

/// A nullifier that uniquely identifies a spent note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nullifier(pub pallas::Base);

impl Nullifier {
    /// Compute the nullifier for a note commitment under a spending key (V1 — legacy).
    ///
    /// `N = PoseidonHash(sk_as_base, commitment)`
    pub fn derive(sk: &SpendingKey, commitment: &NoteCommitment) -> Self {
        let sk_field = scalar_to_base(sk.inner());
        let nf = poseidon::hash_two(sk_field, commitment.inner());
        Self(nf)
    }

    /// Compute a domain-separated nullifier (V2).
    ///
    /// `N = PoseidonHash4(sk_as_base, commitment, chain_id, app_id)`
    ///
    /// This ensures the same (sk, commitment) pair produces a different
    /// nullifier on each chain/app, preventing cross-domain replay.
    pub fn derive_v2(
        sk: &SpendingKey,
        commitment: &NoteCommitment,
        domain: &NullifierDomain,
    ) -> Self {
        let sk_field = scalar_to_base(sk.inner());
        let nf = poseidon::hash_four(
            sk_field,
            commitment.inner(),
            pallas::Base::from(domain.chain_id),
            pallas::Base::from(domain.app_id),
        );
        Self(nf)
    }

    /// Compute a child nullifier derived from a parent nullifier on another domain.
    ///
    /// `child_nf = PoseidonHash4(parent_nf, child_chain_id, child_app_id, link_nonce)`
    ///
    /// This enables cross-domain nullifier linking: a parent nullifier on chain A
    /// can produce a deterministic child nullifier on chain B without revealing
    /// the spending key.
    pub fn derive_child(
        parent_nf: &Nullifier,
        child_domain: &NullifierDomain,
        link_nonce: u64,
    ) -> Self {
        let nf = poseidon::hash_four(
            parent_nf.0,
            pallas::Base::from(child_domain.chain_id),
            pallas::Base::from(child_domain.app_id),
            pallas::Base::from(link_nonce),
        );
        Self(nf)
    }

    /// The raw field element.
    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use crate::note::{Note, NATIVE_ASSET};
    use pasta_curves::pallas;
    use proptest::prelude::*;

    #[test]
    fn nullifier_deterministic() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let nf1 = Nullifier::derive(&sk, &cm);
        let nf2 = Nullifier::derive(&sk, &cm);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn different_keys_different_nullifiers() {
        let sk1 = SpendingKey::from_scalar(pallas::Scalar::from(1u64));
        let sk2 = SpendingKey::from_scalar(pallas::Scalar::from(2u64));
        let note = Note::with_randomness(&sk1, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let nf1 = Nullifier::derive(&sk1, &cm);
        let nf2 = Nullifier::derive(&sk2, &cm);
        assert_ne!(nf1, nf2, "Different spending keys must produce different nullifiers");
    }

    #[test]
    fn different_commitments_different_nullifiers() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let n1 = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let n2 = Note::with_randomness(&sk, 200, NATIVE_ASSET, pallas::Scalar::from(2u64));
        let nf1 = Nullifier::derive(&sk, &NoteCommitment::from_note(&n1));
        let nf2 = Nullifier::derive(&sk, &NoteCommitment::from_note(&n2));
        assert_ne!(nf1, nf2);
    }

    // --- V2 domain-separated nullifier tests ---

    #[test]
    fn v2_nullifier_deterministic() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let domain = NullifierDomain::new(1, 1);
        let nf1 = Nullifier::derive_v2(&sk, &cm, &domain);
        let nf2 = Nullifier::derive_v2(&sk, &cm, &domain);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn v2_different_domains_different_nullifiers() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let domain_a = NullifierDomain::new(1, 1);
        let domain_b = NullifierDomain::new(2, 1);
        let nf_a = Nullifier::derive_v2(&sk, &cm, &domain_a);
        let nf_b = Nullifier::derive_v2(&sk, &cm, &domain_b);
        assert_ne!(nf_a, nf_b, "Different chain_ids must produce different nullifiers");
    }

    #[test]
    fn v2_different_app_ids_different_nullifiers() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let domain_a = NullifierDomain::new(1, 1);
        let domain_b = NullifierDomain::new(1, 2);
        let nf_a = Nullifier::derive_v2(&sk, &cm, &domain_a);
        let nf_b = Nullifier::derive_v2(&sk, &cm, &domain_b);
        assert_ne!(nf_a, nf_b, "Different app_ids must produce different nullifiers");
    }

    #[test]
    fn v2_differs_from_v1() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let nf_v1 = Nullifier::derive(&sk, &cm);
        let nf_v2 = Nullifier::derive_v2(&sk, &cm, &NullifierDomain::default());
        assert_ne!(nf_v1, nf_v2, "V2 nullifiers must differ from V1 even with zero domain");
    }

    // --- Cross-domain child nullifier tests ---

    #[test]
    fn child_nullifier_deterministic() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let parent_domain = NullifierDomain::new(1, 1);
        let parent_nf = Nullifier::derive_v2(&sk, &cm, &parent_domain);
        let child_domain = NullifierDomain::new(2, 1);
        let child1 = Nullifier::derive_child(&parent_nf, &child_domain, 0);
        let child2 = Nullifier::derive_child(&parent_nf, &child_domain, 0);
        assert_eq!(child1, child2);
    }

    #[test]
    fn child_nullifier_different_nonces_differ() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let parent_nf = Nullifier::derive_v2(&sk, &cm, &NullifierDomain::new(1, 1));
        let child_domain = NullifierDomain::new(2, 1);
        let child1 = Nullifier::derive_child(&parent_nf, &child_domain, 0);
        let child2 = Nullifier::derive_child(&parent_nf, &child_domain, 1);
        assert_ne!(child1, child2, "Different nonces must produce different child nullifiers");
    }

    #[test]
    fn child_nullifier_different_child_domains_differ() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let note = Note::with_randomness(&sk, 100, NATIVE_ASSET, pallas::Scalar::from(1u64));
        let cm = NoteCommitment::from_note(&note);
        let parent_nf = Nullifier::derive_v2(&sk, &cm, &NullifierDomain::new(1, 1));
        let child_a = Nullifier::derive_child(&parent_nf, &NullifierDomain::new(2, 1), 0);
        let child_b = Nullifier::derive_child(&parent_nf, &NullifierDomain::new(3, 1), 0);
        assert_ne!(child_a, child_b);
    }

    // -- Property-based tests --

    proptest! {
        /// Nullifier is deterministic for any key and note.
        #[test]
        fn prop_nullifier_deterministic(key in 1u64..u64::MAX, val in 0u64..u64::MAX, r in 1u64..u64::MAX) {
            let sk = SpendingKey::from_scalar(pallas::Scalar::from(key));
            let note = Note::with_randomness(&sk, val, NATIVE_ASSET, pallas::Scalar::from(r));
            let cm = NoteCommitment::from_note(&note);
            prop_assert_eq!(Nullifier::derive(&sk, &cm), Nullifier::derive(&sk, &cm));
        }

        /// Different spending keys yield different nullifiers for the same note.
        #[test]
        fn prop_different_keys_different_nullifiers(k1 in 1u64..u64::MAX, k2 in 1u64..u64::MAX, val in 0u64..u64::MAX, r in 1u64..u64::MAX) {
            prop_assume!(k1 != k2);
            let sk1 = SpendingKey::from_scalar(pallas::Scalar::from(k1));
            let sk2 = SpendingKey::from_scalar(pallas::Scalar::from(k2));
            let note = Note::with_randomness(&sk1, val, NATIVE_ASSET, pallas::Scalar::from(r));
            let cm = NoteCommitment::from_note(&note);
            prop_assert_ne!(Nullifier::derive(&sk1, &cm), Nullifier::derive(&sk2, &cm));
        }

        /// Different notes produce different nullifiers under the same key.
        #[test]
        fn prop_different_notes_different_nullifiers(key in 1u64..u64::MAX, v1 in 0u64..u64::MAX, v2 in 0u64..u64::MAX, r1 in 1u64..u64::MAX, r2 in 1u64..u64::MAX) {
            prop_assume!(v1 != v2 || r1 != r2);
            let sk = SpendingKey::from_scalar(pallas::Scalar::from(key));
            let n1 = Note::with_randomness(&sk, v1, NATIVE_ASSET, pallas::Scalar::from(r1));
            let n2 = Note::with_randomness(&sk, v2, NATIVE_ASSET, pallas::Scalar::from(r2));
            let cm1 = NoteCommitment::from_note(&n1);
            let cm2 = NoteCommitment::from_note(&n2);
            // Only assert different nullifiers when commitments actually differ
            if cm1 != cm2 {
                prop_assert_ne!(Nullifier::derive(&sk, &cm1), Nullifier::derive(&sk, &cm2));
            }
        }

        /// V2 domain separation is injective: different domains → different nullifiers.
        #[test]
        fn prop_v2_domain_injective(
            key in 1u64..u64::MAX,
            val in 0u64..u64::MAX,
            r in 1u64..u64::MAX,
            chain_a in 0u64..u64::MAX,
            chain_b in 0u64..u64::MAX,
            app_a in 0u64..u64::MAX,
            app_b in 0u64..u64::MAX,
        ) {
            prop_assume!(chain_a != chain_b || app_a != app_b);
            let sk = SpendingKey::from_scalar(pallas::Scalar::from(key));
            let note = Note::with_randomness(&sk, val, NATIVE_ASSET, pallas::Scalar::from(r));
            let cm = NoteCommitment::from_note(&note);
            let nf_a = Nullifier::derive_v2(&sk, &cm, &NullifierDomain::new(chain_a, app_a));
            let nf_b = Nullifier::derive_v2(&sk, &cm, &NullifierDomain::new(chain_b, app_b));
            prop_assert_ne!(nf_a, nf_b);
        }
    }
}
