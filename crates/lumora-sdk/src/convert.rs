//! Conversion helpers: `pallas::Base` ↔ hex/bytes.
//!
//! Field elements are serialized as little-endian 32-byte hex strings.
//! Proofs are serialized as raw hex.

use ff::PrimeField;
use pasta_curves::pallas;

/// Encode a `pallas::Base` field element as a 64-char hex string (little-endian).
pub fn field_to_hex(f: pallas::Base) -> String {
    hex::encode(f.to_repr())
}

/// Decode a 64-char hex string to a `pallas::Base`.
/// Returns `None` if the hex is invalid or the value is not in the field.
pub fn hex_to_field(s: &str) -> Option<pallas::Base> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);
    pallas::Base::from_repr(repr).into()
}

/// Encode raw proof bytes as hex.
pub fn proof_to_hex(proof_bytes: &[u8]) -> String {
    hex::encode(proof_bytes)
}

/// Decode hex-encoded proof bytes.
pub fn hex_to_proof(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Encode a `pallas::Base` to 32 raw bytes (little-endian).
pub fn field_to_bytes(f: pallas::Base) -> [u8; 32] {
    f.to_repr()
}

/// Decode 32 raw bytes to a `pallas::Base`.
pub fn bytes_to_field(bytes: &[u8; 32]) -> Option<pallas::Base> {
    pallas::Base::from_repr(*bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_hex_roundtrip() {
        let val = pallas::Base::from(12345u64);
        let hex_str = field_to_hex(val);
        let recovered = hex_to_field(&hex_str).expect("should decode");
        assert_eq!(val, recovered);
    }

    #[test]
    fn field_bytes_roundtrip() {
        let val = pallas::Base::from(99999u64);
        let bytes = field_to_bytes(val);
        let recovered = bytes_to_field(&bytes).expect("should decode");
        assert_eq!(val, recovered);
    }

    #[test]
    fn proof_hex_roundtrip() {
        let proof = vec![0xde, 0xad, 0xbe, 0xef, 0x42];
        let hex_str = proof_to_hex(&proof);
        let recovered = hex_to_proof(&hex_str).expect("should decode");
        assert_eq!(proof, recovered);
    }

    #[test]
    fn bad_hex_returns_none() {
        assert!(hex_to_field("not_valid_hex").is_none());
        assert!(hex_to_field("aabb").is_none()); // too short
    }
}
