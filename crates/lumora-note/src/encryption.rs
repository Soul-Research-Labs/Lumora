//! Note encryption — ECDH + ChaCha20-Poly1305 for private note relay.
//!
//! When creating output notes, the sender encrypts the note details so only
//! the recipient can decrypt them. This uses:
//!
//! 1. Ephemeral Diffie-Hellman on Pallas curve
//! 2. SHA-256 KDF to derive a 32-byte symmetric key from the shared point
//! 3. ChaCha20-Poly1305 AEAD for authenticated encryption
//!
//! # Wire format
//!
//! | Field            | Size    |
//! |------------------|---------|
//! | ephemeral_pubkey | 32 bytes (compressed Pallas point) |
//! | ciphertext       | 48 bytes (encrypted note body)     |
//! | auth_tag         | 16 bytes (Poly1305 tag)            |
//!
//! The note body contains: value (8 bytes) || asset (8 bytes) || randomness (32 bytes).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ff::{Field, PrimeField};
use group::Group;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// Size of the note plaintext: 8 (value) + 8 (asset) + 32 (randomness).
const NOTE_PLAINTEXT_SIZE: usize = 48;

/// Size of the Poly1305 authentication tag.
const AUTH_TAG_SIZE: usize = 16;

/// A fixed nonce is safe here because every encryption uses a unique
/// ephemeral key, so the (key, nonce) pair is never reused.
const FIXED_NONCE: [u8; 12] = [0u8; 12];

/// Encrypt a note for a recipient.
///
/// # Arguments
/// - `recipient_pk`: the recipient's public key point on Pallas.
/// - `value`: note value.
/// - `asset`: asset identifier.
/// - `randomness`: note randomness (as scalar).
/// - `rng`: source of randomness for the ephemeral key.
///
/// # Returns
/// `(ephemeral_pubkey_bytes, ciphertext_with_tag)`.
pub fn encrypt_note(
    recipient_pk: pallas::Point,
    value: u64,
    asset: u64,
    randomness: pallas::Scalar,
    mut rng: impl RngCore,
) -> Option<([u8; 32], Vec<u8>)> {
    // Generate ephemeral key pair.
    let eph_sk = pallas::Scalar::random(&mut rng);
    let eph_pk = pallas::Point::generator() * eph_sk;

    // ECDH: shared_point = eph_sk * recipient_pk
    let shared_point = recipient_pk * eph_sk;

    // Derive 32-byte symmetric key via SHA-256.
    let key = derive_key(&shared_point)?;

    // Serialize the note plaintext.
    let mut plaintext = [0u8; NOTE_PLAINTEXT_SIZE];
    plaintext[0..8].copy_from_slice(&value.to_le_bytes());
    plaintext[8..16].copy_from_slice(&asset.to_le_bytes());
    plaintext[16..48].copy_from_slice(&randomness.to_repr());

    // Encrypt with ChaCha20-Poly1305.
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from(FIXED_NONCE);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("ChaCha20-Poly1305 encryption should not fail with valid key");

    // Serialize ephemeral public key.
    let eph_pk_bytes = point_to_bytes(&eph_pk);

    Some((eph_pk_bytes, ciphertext))
}

/// Decrypt a note using the recipient's spending key.
///
/// # Arguments
/// - `spending_key`: the recipient's secret scalar.
/// - `eph_pk_bytes`: the ephemeral public key from the encryption.
/// - `ciphertext`: the encrypted note body with auth tag appended.
///
/// # Returns
/// `(value, asset, randomness)` on success.
pub fn decrypt_note(
    spending_key: pallas::Scalar,
    eph_pk_bytes: &[u8; 32],
    ciphertext: &[u8],
) -> Option<(u64, u64, pallas::Scalar)> {
    // Ciphertext must be plaintext + auth tag.
    if ciphertext.len() != NOTE_PLAINTEXT_SIZE + AUTH_TAG_SIZE {
        return None;
    }

    // Reconstruct ephemeral public key.
    let eph_pk = bytes_to_point(eph_pk_bytes)?;

    // ECDH: shared_point = spending_key * eph_pk
    let shared_point = eph_pk * spending_key;

    // Derive the same symmetric key.
    let key = derive_key(&shared_point)?;

    // Decrypt and authenticate with ChaCha20-Poly1305.
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from(FIXED_NONCE);
    let plaintext = cipher.decrypt(&nonce, ciphertext).ok()?;

    if plaintext.len() != NOTE_PLAINTEXT_SIZE {
        return None;
    }

    // Parse.
    let value = u64::from_le_bytes(plaintext[0..8].try_into().ok()?);
    let asset = u64::from_le_bytes(plaintext[8..16].try_into().ok()?);

    let mut repr = [0u8; 32];
    repr.copy_from_slice(&plaintext[16..48]);
    let randomness: Option<pallas::Scalar> = pallas::Scalar::from_repr(repr).into();
    let randomness = randomness?;

    Some((value, asset, randomness))
}

/// Derive a 32-byte symmetric key from a shared ECDH point via SHA-256.
fn derive_key(shared_point: &pallas::Point) -> Option<[u8; 32]> {
    let affine = pallas::Affine::from(*shared_point);
    let ct_coords = affine.coordinates();
    if bool::from(ct_coords.is_none()) {
        return None;
    }
    let x_bytes: [u8; 32] = ct_coords.expect("is_some was true").x().to_repr();

    let mut hasher = Sha256::new();
    hasher.update(b"lumora-note-encryption-v2");
    hasher.update(x_bytes);
    Some(hasher.finalize().into())
}

/// Serialize a Pallas point to 32 bytes (x-coordinate + y-parity bit).
///
/// Format: `[x_le_bytes (32)]` with y-parity encoded in the top bit of byte 31.
fn point_to_bytes(point: &pallas::Point) -> [u8; 32] {
    let affine = pallas::Affine::from(*point);
    let ct_coords = affine.coordinates();
    if bool::from(ct_coords.is_some()) {
        let c = ct_coords.expect("is_some was true");
        let x_bytes = c.x().to_repr();
        let y_bytes = c.y().to_repr();
        let mut out: [u8; 32] = x_bytes;
        let y_is_odd = y_bytes[0] & 1;
        out[31] = (out[31] & 0x7F) | (y_is_odd << 7);
        out
    } else {
        [0u8; 32]
    }
}

/// Deserialize a Pallas point from 32 bytes (x + y-parity in top bit).
///
/// Solves $y^2 = x^3 + 5$ on Pallas and picks the y matching the stored parity.
fn bytes_to_point(bytes: &[u8; 32]) -> Option<pallas::Point> {
    // Extract y-parity from the top bit of byte 31.
    let y_parity = (bytes[31] >> 7) & 1;
    let mut x_bytes = *bytes;
    x_bytes[31] &= 0x7F; // clear the parity bit to recover pure x

    let x: pallas::Base = {
        let opt: Option<pallas::Base> = pallas::Base::from_repr(x_bytes).into();
        opt?
    };

    // Pallas curve: y^2 = x^3 + 5
    let x2 = x.square();
    let x3 = x2 * x;
    let rhs = x3 + pallas::Base::from(5u64);

    // Compute sqrt(rhs). If it doesn't exist, x is not on the curve.
    let y: pallas::Base = {
        let opt: Option<pallas::Base> = rhs.sqrt().into();
        opt?
    };

    // Pick the y with matching parity.
    let y_bytes = y.to_repr();
    let y_is_odd = y_bytes[0] & 1;
    let y_final = if y_is_odd == y_parity {
        y
    } else {
        -y
    };

    // Reconstruct the affine point and convert to projective.
    let affine: Option<pallas::Affine> = pallas::Affine::from_xy(x, y_final).into();
    affine.map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = rand::rngs::OsRng;

        // Recipient's key pair.
        let sk = pallas::Scalar::random(&mut rng);
        let pk = pallas::Point::generator() * sk;

        let value = 42u64;
        let asset = 7u64;
        let randomness = pallas::Scalar::from(12345u64);

        // Full end-to-end roundtrip using the public API.
        let (eph_pk_bytes, ciphertext) = encrypt_note(pk, value, asset, randomness, &mut rng)
            .expect("encrypt_note should succeed for valid point");
        let (dec_value, dec_asset, dec_randomness) =
            decrypt_note(sk, &eph_pk_bytes, &ciphertext).expect("decryption should succeed");

        assert_eq!(dec_value, value);
        assert_eq!(dec_asset, asset);
        assert_eq!(dec_randomness, randomness);
    }

    #[test]
    fn test_point_serialization_roundtrip() {
        let mut rng = rand::rngs::OsRng;
        // Test multiple random points.
        for _ in 0..10 {
            let scalar = pallas::Scalar::random(&mut rng);
            let point = pallas::Point::generator() * scalar;
            let bytes = point_to_bytes(&point);
            let recovered = bytes_to_point(&bytes).expect("should decompress");
            assert_eq!(
                pallas::Affine::from(point),
                pallas::Affine::from(recovered),
                "point roundtrip failed"
            );
        }
    }

    #[test]
    fn test_ciphertext_size() {
        let mut rng = rand::rngs::OsRng;
        let sk = pallas::Scalar::random(&mut rng);
        let pk = pallas::Point::generator() * sk;

        let (_, ciphertext) =
            encrypt_note(pk, 100, 0, pallas::Scalar::from(1u64), &mut rng)
            .expect("encrypt_note should succeed");

        // 48 bytes plaintext + 16 bytes Poly1305 tag = 64 bytes
        assert_eq!(ciphertext.len(), NOTE_PLAINTEXT_SIZE + AUTH_TAG_SIZE);
    }

    #[test]
    fn test_wrong_key_returns_none() {
        let mut rng = rand::rngs::OsRng;

        let sk = pallas::Scalar::random(&mut rng);
        let pk = pallas::Point::generator() * sk;

        let (eph_pk_bytes, ciphertext) =
            encrypt_note(pk, 100, 0, pallas::Scalar::from(1u64), &mut rng)
            .expect("encrypt_note should succeed");

        // A completely different secret key should fail authentication.
        let wrong_sk = pallas::Scalar::random(&mut rng);
        assert!(
            decrypt_note(wrong_sk, &eph_pk_bytes, &ciphertext).is_none(),
            "wrong key must not decrypt"
        );
    }

    #[test]
    fn test_truncated_ciphertext_returns_none() {
        let mut rng = rand::rngs::OsRng;

        let sk = pallas::Scalar::random(&mut rng);
        let pk = pallas::Point::generator() * sk;

        let (eph_pk_bytes, ciphertext) =
            encrypt_note(pk, 50, 1, pallas::Scalar::from(2u64), &mut rng)
            .expect("encrypt_note should succeed");

        // Truncate: drop last byte so length check fails.
        let short = &ciphertext[..ciphertext.len() - 1];
        assert!(
            decrypt_note(sk, &eph_pk_bytes, short).is_none(),
            "truncated ciphertext must fail"
        );
    }

    #[test]
    fn test_tampered_tag_returns_none() {
        let mut rng = rand::rngs::OsRng;

        let sk = pallas::Scalar::random(&mut rng);
        let pk = pallas::Point::generator() * sk;

        let (eph_pk_bytes, mut ciphertext) =
            encrypt_note(pk, 25, 2, pallas::Scalar::from(3u64), &mut rng)
            .expect("encrypt_note should succeed");

        // Flip a byte in the auth tag region (last 16 bytes).
        let tag_start = ciphertext.len() - AUTH_TAG_SIZE;
        ciphertext[tag_start] ^= 0xFF;

        assert!(
            decrypt_note(sk, &eph_pk_bytes, &ciphertext).is_none(),
            "tampered tag must fail"
        );
    }

    #[test]
    fn test_tampered_ciphertext_body_returns_none() {
        let mut rng = rand::rngs::OsRng;

        let sk = pallas::Scalar::random(&mut rng);
        let pk = pallas::Point::generator() * sk;

        let (eph_pk_bytes, mut ciphertext) =
            encrypt_note(pk, 10, 0, pallas::Scalar::from(4u64), &mut rng)
            .expect("encrypt_note should succeed");

        // Flip a byte in the encrypted body (before tag).
        ciphertext[0] ^= 0xFF;

        assert!(
            decrypt_note(sk, &eph_pk_bytes, &ciphertext).is_none(),
            "tampered body must fail authentication"
        );
    }

    #[test]
    fn test_empty_ciphertext_returns_none() {
        let mut rng = rand::rngs::OsRng;
        let sk = pallas::Scalar::random(&mut rng);
        let eph_pk_bytes = [0u8; 32]; // arbitrary
        let empty: &[u8] = &[];
        assert!(
            decrypt_note(sk, &eph_pk_bytes, empty).is_none(),
            "empty ciphertext must fail"
        );
    }
}
