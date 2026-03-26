//! Pedersen commitment on the Pallas curve.
//!
//! A Pedersen commitment hides a value `v` with randomness `r`:
//!
//!   C = v·G + r·H
//!
//! where G and H are independent generator points on Pallas.
//! The commitment is:
//! - **Hiding**: without `r`, the value `v` cannot be recovered.
//! - **Binding**: the committer cannot change `v` after committing.
//! - **Homomorphic**: `C(a) + C(b) = C(a+b)` (with summed randomness).
//!
//! We derive H by hashing "LUMORA_PEDERSEN_H" to a curve point so that
//! the discrete log relationship between G and H is unknown.

use ff::PrimeField;
use group::{Group, GroupEncoding};
use pasta_curves::pallas;
use std::sync::OnceLock;

use crate::poseidon;

/// The primary generator for the value component.
/// This is the standard Pallas generator point.
pub fn generator_g() -> pallas::Point {
    pallas::Point::generator()
}

/// The blinding generator, derived deterministically.
/// `H = hash_to_curve("LUMORA_PEDERSEN_H")`
///
/// We derive H by hashing a domain separator to the curve, ensuring
/// the discrete log between G and H is unknown.
pub fn generator_h() -> pallas::Point {
    // Hash a domain separator to get a seed field element.
    let a = pallas::Base::from(0x5A415345_4F4E5F48u64); // "ZASEON_H" as u64
    let b = pallas::Base::from(0x50454445_5253454Eu64); // "PEDERSEN" as u64
    let seed = poseidon::hash_two(a, b);

    // Try-and-increment: hash seed with counter until we find a valid curve point.
    // Cap at 256 attempts to avoid an infinite loop on unexpected curve/hash changes.
    const MAX_GENERATOR_ATTEMPTS: u32 = 256;
    let mut counter = pallas::Base::zero();
    for attempt in 0..MAX_GENERATOR_ATTEMPTS {
        let x = poseidon::hash_two(seed, counter);
        let repr = x.to_repr();
        let ct_opt = pallas::Affine::from_bytes(&repr);
        if bool::from(ct_opt.is_some()) {
            let affine: pallas::Affine = ct_opt.expect("is_some() was true");
            let pt: pallas::Point = affine.into();
            if !bool::from(pt.is_identity()) {
                return pt;
            }
        }
        counter += pallas::Base::one();
        let _ = attempt; // suppress unused warning on the last iteration
    }
    panic!(
        "Pedersen generator_h: no valid curve point found after {} attempts; \
         check Poseidon hash or curve parameters",
        MAX_GENERATOR_ATTEMPTS
    );
}

/// Pedersen commitment: `C = value·G + randomness·H`
///
/// Both `value` and `randomness` are Pallas scalars (Fq).
pub fn commit(value: pallas::Scalar, randomness: pallas::Scalar) -> pallas::Point {
    static H: OnceLock<pallas::Point> = OnceLock::new();
    let g = generator_g();
    let h = *H.get_or_init(generator_h);
    g * value + h * randomness
}

/// Commit using a u64 value (convenience wrapper).
pub fn commit_u64(value: u64, randomness: pallas::Scalar) -> pallas::Point {
    commit(pallas::Scalar::from(value), randomness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::{Curve, Group};
    use rand::rngs::OsRng;

    #[test]
    fn generators_are_different() {
        let g = generator_g();
        let h = generator_h();
        assert_ne!(
            g.to_affine(),
            h.to_affine(),
            "G and H must be distinct points"
        );
    }

    #[test]
    fn generator_h_is_not_identity() {
        let h = generator_h();
        assert!(!bool::from(h.is_identity()));
    }

    #[test]
    fn commitment_hiding() {
        // Same value, different randomness → different commitments
        let v = pallas::Scalar::from(100u64);
        let r1 = pallas::Scalar::random(OsRng);
        let r2 = pallas::Scalar::random(OsRng);
        let c1 = commit(v, r1);
        let c2 = commit(v, r2);
        assert_ne!(c1.to_affine(), c2.to_affine());
    }

    #[test]
    fn commitment_binding() {
        // Different values, same randomness → different commitments
        let r = pallas::Scalar::random(OsRng);
        let c1 = commit(pallas::Scalar::from(100u64), r);
        let c2 = commit(pallas::Scalar::from(200u64), r);
        assert_ne!(c1.to_affine(), c2.to_affine());
    }

    #[test]
    fn commitment_homomorphic() {
        // C(a, r1) + C(b, r2) == C(a+b, r1+r2)
        let a = pallas::Scalar::from(42u64);
        let b = pallas::Scalar::from(58u64);
        let r1 = pallas::Scalar::random(OsRng);
        let r2 = pallas::Scalar::random(OsRng);

        let c_a = commit(a, r1);
        let c_b = commit(b, r2);
        let c_sum = commit(a + b, r1 + r2);

        assert_eq!(
            (c_a + c_b).to_affine(),
            c_sum.to_affine(),
            "Pedersen commitments must be additively homomorphic"
        );
    }
}
