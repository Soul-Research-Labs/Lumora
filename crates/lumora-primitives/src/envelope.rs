//! Fixed-size proof envelopes — metadata resistance via constant-size messages.
//!
//! Inspired by ZASEON's FIXED_PAYLOAD_SIZE: all proofs are padded to a
//! uniform size before transmission. This prevents observers from inferring
//! the operation type (deposit vs. transfer vs. withdrawal) based on proof
//! size differences.
//!
//! The envelope format:
//! ```text
//! [4 bytes: payload length (little-endian u32)]
//! [N bytes: actual proof data]
//! [P bytes: random padding to reach ENVELOPE_SIZE]
//! ```

use rand_core::RngCore;

/// Fixed envelope size in bytes (2 KB).
///
/// All proofs are padded to this size. Chosen to exceed the maximum possible
/// proof size for any circuit in the system.
pub const ENVELOPE_SIZE: usize = 2048;

/// Minimum envelope size (should always accommodate the 4-byte length header).
const HEADER_SIZE: usize = 4;

/// Maximum payload that can fit in an envelope.
pub const MAX_PAYLOAD_SIZE: usize = ENVELOPE_SIZE - HEADER_SIZE;

/// Error type for envelope operations.
#[derive(Debug, Clone)]
pub enum EnvelopeError {
    /// Payload exceeds the maximum envelope capacity.
    PayloadTooLarge { size: usize, max: usize },
    /// Envelope data is too short or corrupted.
    InvalidEnvelope,
    /// Length header is inconsistent with envelope contents.
    InvalidLength,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge { size, max } => {
                write!(f, "payload too large: {size} bytes (max {max})")
            }
            Self::InvalidEnvelope => write!(f, "invalid or corrupted envelope"),
            Self::InvalidLength => write!(f, "envelope length header is invalid"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Wrap proof bytes into a fixed-size envelope with random padding.
///
/// The padding uses random bytes (not zeros) to prevent distinguishing
/// between padding and payload via entropy analysis.
pub fn seal(payload: &[u8], rng: &mut impl RngCore) -> Result<Vec<u8>, EnvelopeError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(EnvelopeError::PayloadTooLarge {
            size: payload.len(),
            max: MAX_PAYLOAD_SIZE,
        });
    }

    let mut envelope = Vec::with_capacity(ENVELOPE_SIZE);

    // Write length header (little-endian u32).
    let len = payload.len() as u32;
    envelope.extend_from_slice(&len.to_le_bytes());

    // Write actual payload.
    envelope.extend_from_slice(payload);

    // Fill remaining space with random bytes.
    let padding_len = ENVELOPE_SIZE - envelope.len();
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);
    envelope.extend_from_slice(&padding);

    debug_assert_eq!(envelope.len(), ENVELOPE_SIZE);
    Ok(envelope)
}

/// Extract proof bytes from a fixed-size envelope.
pub fn open(envelope: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if envelope.len() != ENVELOPE_SIZE {
        return Err(EnvelopeError::InvalidEnvelope);
    }

    let len = u32::from_le_bytes(
        envelope[..HEADER_SIZE]
            .try_into()
            .map_err(|_| EnvelopeError::InvalidEnvelope)?,
    ) as usize;

    if len > MAX_PAYLOAD_SIZE {
        return Err(EnvelopeError::InvalidLength);
    }

    let end = HEADER_SIZE + len;
    if end > envelope.len() {
        return Err(EnvelopeError::InvalidLength);
    }

    Ok(envelope[HEADER_SIZE..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn seal_open_roundtrip() {
        let payload = b"hello world proof data";
        let envelope = seal(payload, &mut OsRng).expect("seal");
        assert_eq!(envelope.len(), ENVELOPE_SIZE);
        let recovered = open(&envelope).expect("open");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn envelope_always_fixed_size() {
        // Different payload sizes all produce the same envelope size.
        for size in [0, 1, 100, 500, 1000, MAX_PAYLOAD_SIZE] {
            let payload = vec![0xAB; size];
            let envelope = seal(&payload, &mut OsRng).expect("seal");
            assert_eq!(
                envelope.len(),
                ENVELOPE_SIZE,
                "envelope must be exactly {ENVELOPE_SIZE} bytes, got {}",
                envelope.len()
            );
        }
    }

    #[test]
    fn payload_too_large_rejected() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(seal(&payload, &mut OsRng).is_err());
    }

    #[test]
    fn different_padding_each_time() {
        let payload = b"same payload";
        let e1 = seal(payload, &mut OsRng).expect("seal");
        let e2 = seal(payload, &mut OsRng).expect("seal");
        // Payloads match but envelopes differ due to random padding.
        assert_ne!(e1, e2, "random padding should make envelopes differ");
        // But the extracted payloads must match.
        assert_eq!(open(&e1).unwrap(), open(&e2).unwrap());
    }

    #[test]
    fn empty_payload() {
        let envelope = seal(b"", &mut OsRng).expect("seal");
        assert_eq!(envelope.len(), ENVELOPE_SIZE);
        let recovered = open(&envelope).expect("open");
        assert!(recovered.is_empty());
    }

    #[test]
    fn invalid_envelope_size_rejected() {
        assert!(open(&[0u8; 100]).is_err());
        assert!(open(&[]).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    proptest! {
        #[test]
        fn seal_open_roundtrip_arbitrary(payload in proptest::collection::vec(any::<u8>(), 0..=MAX_PAYLOAD_SIZE)) {
            let envelope = seal(&payload, &mut OsRng).expect("seal must succeed for valid payloads");
            prop_assert_eq!(envelope.len(), ENVELOPE_SIZE);
            let recovered = open(&envelope).expect("open must succeed for sealed envelopes");
            prop_assert_eq!(recovered, payload);
        }

        #[test]
        fn open_never_panics_on_arbitrary_data(data in proptest::collection::vec(any::<u8>(), 0..=ENVELOPE_SIZE + 100)) {
            // open() must return Result, never panic
            let _ = open(&data);
        }

        #[test]
        fn sealed_envelope_always_fixed_size(size in 0..=MAX_PAYLOAD_SIZE) {
            let payload = vec![0xABu8; size];
            let envelope = seal(&payload, &mut OsRng).expect("seal");
            prop_assert_eq!(envelope.len(), ENVELOPE_SIZE);
        }
    }
}
