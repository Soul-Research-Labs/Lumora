//! Spending and viewing keys.
//!
//! - **SpendingKey**: a secret scalar that authorizes note consumption.
//! - **ViewingKey**: derived from the spending key, allows decrypting and scanning
//!   notes without spending authority. Used for auditing / compliance.
//!
//! Public key = spending_key · G  (Pallas generator)

use ff::{Field, PrimeField};
use group::Group;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;
use rand_core::RngCore;
use serde;
use zeroize::Zeroizing;

/// A secret key that authorizes spending a note.
#[derive(Clone)]
pub struct SpendingKey(pallas::Scalar);

impl std::fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpendingKey(<redacted>)")
    }
}

impl Drop for SpendingKey {
    fn drop(&mut self) {
        // Overwrite the scalar with zero to prevent key leakage.
        // We avoid unsafe pointer casts — instead, replace the scalar value
        // in-place with the zero element.
        self.0 = pallas::Scalar::ZERO;
    }
}

impl serde::Serialize for SpendingKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.to_repr();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> serde::Deserialize<'de> for SpendingKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            serde::Deserialize::deserialize(deserializer)?
        );
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("spending key must be 32 bytes"));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&bytes);
        let scalar: Option<pallas::Scalar> = pallas::Scalar::from_repr(*arr).into();
        match scalar {
            Some(s) => Ok(Self(s)),
            None => Err(serde::de::Error::custom("invalid scalar")),
        }
    }
}

impl SpendingKey {
    /// Generate a random spending key.
    pub fn random(rng: impl RngCore) -> Self {
        Self(pallas::Scalar::random(rng))
    }

    /// Create from a known scalar (for testing / deserialization).
    pub fn from_scalar(s: pallas::Scalar) -> Self {
        Self(s)
    }

    /// The raw scalar value.
    pub fn inner(&self) -> pallas::Scalar {
        self.0
    }

    /// Derive the corresponding public key: `pk = sk · G`.
    pub fn public_key(&self) -> pallas::Point {
        pallas::Point::generator() * self.0
    }

    /// The spending key as a base field element.
    ///
    /// In the circuit, we use the spending key directly as the "owner" field
    /// in the commitment hash (the circuit never does EC scalar multiplication).
    /// This is secure because the spending key is secret and Poseidon is one-way.
    pub fn public_key_field(&self) -> pallas::Base {
        scalar_to_base(self.0)
    }

    /// Derive a viewing key from this spending key.
    pub fn viewing_key(&self) -> ViewingKey {
        ViewingKey {
            key: lumora_primitives::poseidon::hash_one(scalar_to_base(self.0)),
        }
    }

    /// Derive a child spending key at the given index.
    ///
    /// Uses Poseidon-based derivation: `child = Poseidon(parent_field, index)`,
    /// interpreting the result as a new scalar.  This provides a ZK-native
    /// key hierarchy similar to BIP-32 but suitable for Pallas curves.
    pub fn derive_child(&self, index: u32) -> Self {
        let parent_base = scalar_to_base(self.0);
        let idx_base = pallas::Base::from(index as u64);
        let child_base = lumora_primitives::poseidon::hash_two(parent_base, idx_base);
        let child_bytes = child_base.to_repr();
        // The result of Poseidon over Fp is always a valid Fp element,
        // and Fp ≈ Fq for Pallas/Vesta, so from_repr virtually always succeeds.
        let scalar: Option<pallas::Scalar> = pallas::Scalar::from_repr(child_bytes).into();
        match scalar {
            Some(s) => Self(s),
            None => {
                // Extremely unlikely: hash again to break out of edge case.
                let rehashed = lumora_primitives::poseidon::hash_one(child_base);
                Self(pallas::Scalar::from_repr(rehashed.to_repr())
                    .expect("poseidon output is always a valid scalar"))
            }
        }
    }

    /// Derive a spending key from this parent key using a BIP-44-style path.
    ///
    /// Each element of `path` is applied as a sequential child derivation:
    /// `derive_path(&[44, 0, 0])` yields `self.derive_child(44).derive_child(0).derive_child(0)`.
    pub fn derive_path(&self, path: &[u32]) -> Self {
        let mut key = self.clone();
        for &index in path {
            key = key.derive_child(index);
        }
        key
    }

    /// Generate a new random mnemonic and derive a spending key from it.
    ///
    /// Returns `(mnemonic_phrase, spending_key)`.  The caller must store
    /// the mnemonic words securely — they are the only way to recover the key.
    #[cfg(feature = "mnemonic")]
    pub fn generate_mnemonic(mut rng: impl RngCore) -> (String, Self) {
        let mut entropy = Zeroizing::new([0u8; 32]); // 256-bit entropy → 24-word mnemonic
        rng.fill_bytes(entropy.as_mut());
        let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy.as_ref())
            .expect("32 bytes is valid entropy");
        let phrase = mnemonic.to_string();
        let key = Self::from_mnemonic(&phrase);
        (phrase, key)
    }

    /// Recover a spending key from a BIP-39 mnemonic phrase.
    ///
    /// Uses the mnemonic's 64-byte seed (no passphrase) and takes the first
    /// 32 bytes as the scalar representation, reducing into the Pallas scalar
    /// field.
    #[cfg(feature = "mnemonic")]
    pub fn from_mnemonic(phrase: &str) -> Self {
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
            .expect("valid mnemonic");
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&seed[..32]);
        // Interpret as a scalar — from_repr may fail if >= field modulus,
        // so fall back to wide reduction (from_u512 is not available, so we
        // hash via Poseidon to get a valid field element deterministically).
        let scalar: Option<pallas::Scalar> = pallas::Scalar::from_repr(*bytes).into();
        match scalar {
            Some(s) => Self(s),
            None => {
                // Bytes >= field modulus: use the second 32 bytes of the
                // 64-byte BIP-39 seed as a domain separator and hash both
                // halves through Poseidon for a deterministic, uniform scalar.
                let mut domain_bytes = Zeroizing::new([0u8; 32]);
                domain_bytes.copy_from_slice(&seed[32..64]);
                // At least one of the two halves will be a valid base field
                // element (the field modulus is ~2^254, so random 32-byte
                // values have >93% chance of being valid).
                let a = pallas::Base::from_repr(*bytes)
                    .unwrap_or_else(|| {
                        let mut b = *bytes;
                        b[31] &= 0x3F; // force valid for base field
                        pallas::Base::from_repr(b)
                            .expect("cleared top bits guarantees valid base field element")
                    });
                let b = pallas::Base::from_repr(*domain_bytes)
                    .unwrap_or_else(|| {
                        let mut d = *domain_bytes;
                        d[31] &= 0x3F;
                        pallas::Base::from_repr(d)
                            .expect("cleared top bits guarantees valid base field element")
                    });
                let hashed = lumora_primitives::poseidon::hash_two(a, b);
                let hashed_bytes = hashed.to_repr();
                Self(pallas::Scalar::from_repr(hashed_bytes)
                    .expect("poseidon output is always a valid scalar"))
            }
        }
    }
}

/// A key that allows scanning / decrypting notes without spending authority.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ViewingKey {
    #[serde(with = "lumora_primitives::serde_field::base")]
    pub key: pallas::Base,
}

impl ViewingKey {
    /// Derive the recipient tag (32 bytes) used for note store lookups.
    pub fn tag(&self) -> [u8; 32] {
        self.key.to_repr()
    }

    /// Serialize to 32-byte canonical representation for disclosure.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_repr()
    }

    /// Deserialize from a 32-byte representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let base: Option<pallas::Base> = pallas::Base::from_repr(bytes).into();
        base.map(|key| Self { key })
    }

    /// Hex-encode the viewing key for human-readable disclosure.
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        let mut hex = String::with_capacity(64);
        for b in &bytes {
            use std::fmt::Write;
            // write! to String is infallible
            let _ = write!(hex, "{:02x}", b);
        }
        hex
    }

    /// Decode a hex-encoded viewing key.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        Self::from_bytes(bytes)
    }

    /// Check whether a note's owner matches this viewing key.
    ///
    /// Returns true if `Poseidon(owner_field) == self.key`, meaning
    /// this viewing key can decrypt/scan notes owned by that owner.
    pub fn owns_note_from(&self, owner_field: pallas::Base) -> bool {
        let tag = recipient_tag(owner_field);
        tag == self.tag()
    }
}

/// Derive a recipient tag from a public owner field.
///
/// This lets a sender compute the tag without knowing the full viewing key,
/// since `tag = Poseidon(owner_field).to_repr()` matches `ViewingKey::tag()`.
pub fn recipient_tag(owner_field: pallas::Base) -> [u8; 32] {
    lumora_primitives::poseidon::hash_one(owner_field).to_repr()
}

// ---------------------------------------------------------------------------
// Stealth addresses
// ---------------------------------------------------------------------------

/// Metadata a sender publishes alongside a stealth note.
///
/// The recipient scans for notes by attempting `stealth_receive` with their
/// spending key against each `StealthMeta` on-chain.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StealthMeta {
    /// The sender's ephemeral public key (compressed affine point).
    #[serde(with = "point_serde")]
    pub ephemeral_pk: pallas::Affine,
    /// The one-time owner field used in the note commitment.
    #[serde(with = "lumora_primitives::serde_field::base")]
    pub one_time_owner: pallas::Base,
}

/// Create a stealth note for `recipient_pk`.
///
/// Returns `(one_time_owner_field, stealth_meta)`.  The caller uses
/// `one_time_owner_field` as the note's `owner_pub` when constructing
/// the `Note` commitment, and publishes `stealth_meta` alongside it so
/// the recipient can detect and spend the note.
///
/// Protocol:
/// 1. sender picks ephemeral secret `r`
/// 2. shared secret `S = r · recipient_pk`
/// 3. `tweak = Poseidon(S.x)`
/// 4. one-time owner = `Poseidon(recipient_pk_field, tweak)`
pub fn stealth_send(
    recipient_pk: pallas::Point,
    rng: impl RngCore,
) -> Option<(pallas::Base, StealthMeta)> {
    use group::Curve;
    let r = pallas::Scalar::random(rng);
    let ephemeral_pk = (pallas::Point::generator() * r).to_affine();
    let shared = recipient_pk * r;
    let shared_coords = shared.to_affine().coordinates();
    if bool::from(shared_coords.is_none()) { return None; }
    let shared_x = *shared_coords.expect("is_some was true").x();
    let tweak = lumora_primitives::poseidon::hash_one(shared_x);

    let recipient_affine = recipient_pk.to_affine();
    let recip_coords = recipient_affine.coordinates();
    if bool::from(recip_coords.is_none()) { return None; }
    let recip_x = *recip_coords.expect("is_some was true").x();
    let one_time_owner =
        lumora_primitives::poseidon::hash_two(recip_x, tweak);

    let meta = StealthMeta {
        ephemeral_pk,
        one_time_owner,
    };
    Some((one_time_owner, meta))
}

impl SpendingKey {
    /// Try to detect and derive the one-time spending field for a stealth note.
    ///
    /// Returns `Some(one_time_spending_field)` if the note was addressed to us.
    pub fn stealth_receive(&self, meta: &StealthMeta) -> Option<pallas::Base> {
        use ff::PrimeField;
        use group::Curve;
        use subtle::ConstantTimeEq;
        let shared = pallas::Point::from(meta.ephemeral_pk) * self.0;
        let shared_coords = shared.to_affine().coordinates();
        if bool::from(shared_coords.is_none()) { return None; }
        let shared_x = *shared_coords.expect("is_some was true").x();
        let tweak = lumora_primitives::poseidon::hash_one(shared_x);

        let my_pk_coords = self.public_key().to_affine().coordinates();
        if bool::from(my_pk_coords.is_none()) { return None; }
        let my_pk_x = *my_pk_coords.expect("is_some was true").x();
        let expected_owner =
            lumora_primitives::poseidon::hash_two(my_pk_x, tweak);

        // Constant-time comparison to avoid leaking whether this note is ours.
        if bool::from(expected_owner.to_repr().ct_eq(&meta.one_time_owner.to_repr())) {
            Some(expected_owner)
        } else {
            None
        }
    }
}

/// Minimal serde for `pallas::Affine` via uncompressed x/y coordinates.
mod point_serde {
    use ff::PrimeField;
    use pasta_curves::arithmetic::CurveAffine;
    use pasta_curves::pallas;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct AffineRep {
        x: [u8; 32],
        y: [u8; 32],
    }

    pub fn serialize<S: Serializer>(pt: &pallas::Affine, s: S) -> Result<S::Ok, S::Error> {
        let coords = pt.coordinates();
        if bool::from(coords.is_none()) {
            return Err(serde::ser::Error::custom("cannot serialize identity point"));
        }
        let coords = coords.expect("is_some was true");
        let rep = AffineRep {
            x: coords.x().to_repr(),
            y: coords.y().to_repr(),
        };
        rep.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<pallas::Affine, D::Error> {
        let rep = AffineRep::deserialize(d)?;
        let x: Option<pallas::Base> = pallas::Base::from_repr(rep.x).into();
        let y: Option<pallas::Base> = pallas::Base::from_repr(rep.y).into();
        match (x, y) {
            (Some(x_val), Some(y_val)) => {
                let pt = pallas::Affine::from_xy(x_val, y_val);
                if pt.is_some().into() {
                    Ok(pt.expect("is_some() was true"))
                } else {
                    Err(serde::de::Error::custom("point not on curve"))
                }
            }
            _ => Err(serde::de::Error::custom("invalid field element")),
        }
    }
}

/// Convert a Pallas scalar to a Pallas base field element.
/// Both fields are ~2^254, so we reduce modulo the base field prime.
pub fn scalar_to_base(s: pallas::Scalar) -> pallas::Base {
    let repr = s.to_repr();
    pallas::Base::from_repr(repr).unwrap_or_else(|| {
        // If the scalar exceeds Fp, reduce by hashing all 32 bytes.
        let a = u64::from_le_bytes(repr[0..8].try_into()
            .expect("repr is 32 bytes"));
        let b = u64::from_le_bytes(repr[8..16].try_into()
            .expect("repr is 32 bytes"));
        let c = u64::from_le_bytes(repr[16..24].try_into()
            .expect("repr is 32 bytes"));
        let d = u64::from_le_bytes(repr[24..32].try_into()
            .expect("repr is 32 bytes"));
        let left = lumora_primitives::poseidon::hash_two(
            pallas::Base::from(a),
            pallas::Base::from(b),
        );
        let right = lumora_primitives::poseidon::hash_two(
            pallas::Base::from(c),
            pallas::Base::from(d),
        );
        lumora_primitives::poseidon::hash_two(left, right)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::Curve;
    use rand::rngs::OsRng;

    #[test]
    fn spending_key_generates_valid_pubkey() {
        let sk = SpendingKey::random(OsRng);
        let pk = sk.public_key();
        assert!(!bool::from(pk.is_identity()));
    }

    #[test]
    fn viewing_key_deterministic() {
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(12345u64));
        let vk1 = sk.viewing_key();
        let vk2 = sk.viewing_key();
        assert_eq!(vk1.key, vk2.key);
    }

    #[test]
    fn different_keys_different_pubkeys() {
        let sk1 = SpendingKey::from_scalar(pallas::Scalar::from(1u64));
        let sk2 = SpendingKey::from_scalar(pallas::Scalar::from(2u64));
        assert_ne!(sk1.public_key().to_affine(), sk2.public_key().to_affine());
    }

    #[test]
    fn mnemonic_roundtrip() {
        let (phrase, key1) = SpendingKey::generate_mnemonic(OsRng);
        assert_eq!(phrase.split_whitespace().count(), 24);
        let key2 = SpendingKey::from_mnemonic(&phrase);
        assert_eq!(key1.inner(), key2.inner(), "same mnemonic must produce same key");
    }

    #[test]
    fn mnemonic_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let k1 = SpendingKey::from_mnemonic(phrase);
        let k2 = SpendingKey::from_mnemonic(phrase);
        assert_eq!(k1.inner(), k2.inner());
        // Key should be non-zero
        assert_ne!(k1.inner(), pallas::Scalar::ZERO);
    }

    #[test]
    fn child_key_derivation_deterministic() {
        let parent = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let c1 = parent.derive_child(0);
        let c2 = parent.derive_child(0);
        assert_eq!(c1.inner(), c2.inner());
    }

    #[test]
    fn child_key_different_indices_differ() {
        let parent = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
        let c0 = parent.derive_child(0);
        let c1 = parent.derive_child(1);
        assert_ne!(c0.inner(), c1.inner());
    }

    #[test]
    fn derive_path_matches_sequential_children() {
        let parent = SpendingKey::from_scalar(pallas::Scalar::from(99u64));
        let via_path = parent.derive_path(&[44, 0, 0]);
        let via_seq = parent.derive_child(44).derive_child(0).derive_child(0);
        assert_eq!(via_path.inner(), via_seq.inner());
    }

    // --- Stealth address tests ---

    #[test]
    fn stealth_roundtrip_recipient_can_detect() {
        let recipient = SpendingKey::random(OsRng);
        let recipient_pk = recipient.public_key();
        let (_owner, meta) = stealth_send(recipient_pk, OsRng).unwrap();
        assert!(recipient.stealth_receive(&meta).is_some());
    }

    #[test]
    fn stealth_non_recipient_cannot_detect() {
        let recipient = SpendingKey::random(OsRng);
        let bystander = SpendingKey::random(OsRng);
        let recipient_pk = recipient.public_key();
        let (_owner, meta) = stealth_send(recipient_pk, OsRng).unwrap();
        assert!(bystander.stealth_receive(&meta).is_none());
    }

    #[test]
    fn stealth_owner_matches_meta() {
        let recipient = SpendingKey::random(OsRng);
        let recipient_pk = recipient.public_key();
        let (owner, meta) = stealth_send(recipient_pk, OsRng).unwrap();
        assert_eq!(owner, meta.one_time_owner);
        let detected = recipient.stealth_receive(&meta).unwrap();
        assert_eq!(detected, owner);
    }

    #[test]
    fn stealth_different_sends_produce_different_owners() {
        let recipient = SpendingKey::random(OsRng);
        let pk = recipient.public_key();
        let (owner1, _) = stealth_send(pk, OsRng).unwrap();
        let (owner2, _) = stealth_send(pk, OsRng).unwrap();
        // Overwhelmingly likely to differ due to different ephemeral keys
        assert_ne!(owner1, owner2);
    }

    #[test]
    fn stealth_meta_serde_roundtrip() {
        let recipient = SpendingKey::random(OsRng);
        let (_, meta) = stealth_send(recipient.public_key(), OsRng).unwrap();
        let json = serde_json::to_string(&meta).unwrap();
        let meta2: StealthMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta.one_time_owner, meta2.one_time_owner);
        assert_eq!(meta.ephemeral_pk, meta2.ephemeral_pk);
    }

    // ── BIP-39 mnemonic edge-case tests ─────────────────────────────

    #[test]
    fn mnemonic_different_phrases_different_keys() {
        let (phrase_a, key_a) = SpendingKey::generate_mnemonic(OsRng);
        let (phrase_b, key_b) = SpendingKey::generate_mnemonic(OsRng);
        assert_ne!(phrase_a, phrase_b);
        assert_ne!(key_a.inner(), key_b.inner());
    }

    #[test]
    fn mnemonic_derived_key_is_nonzero() {
        let (_, key) = SpendingKey::generate_mnemonic(OsRng);
        assert_ne!(key.inner(), pallas::Scalar::ZERO);
    }

    #[test]
    fn mnemonic_viewing_key_deterministic_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let vk1 = SpendingKey::from_mnemonic(phrase).viewing_key();
        let vk2 = SpendingKey::from_mnemonic(phrase).viewing_key();
        assert_eq!(vk1.key, vk2.key);
    }

    #[test]
    fn mnemonic_child_derivation_stable() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let parent = SpendingKey::from_mnemonic(phrase);
        let child = parent.derive_path(&[44, 0, 0]);
        let child2 = SpendingKey::from_mnemonic(phrase).derive_path(&[44, 0, 0]);
        assert_eq!(child.inner(), child2.inner());
    }
}
