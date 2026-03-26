//! Serde helpers for Pallas field elements.
//!
//! `pallas::Base` and `pallas::Scalar` don't implement serde natively.
//! These modules provide `serialize`/`deserialize` functions usable with
//! `#[serde(with = "…")]` on struct fields.

use ff::PrimeField;

/// Serde support for `pallas::Base` (Fp).
pub mod base {
    use super::*;
    use pasta_curves::pallas;

    pub fn serialize<S: serde::Serializer>(val: &pallas::Base, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&val.to_repr())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<pallas::Base, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes for pallas::Base"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let opt: Option<pallas::Base> = pallas::Base::from_repr(arr).into();
        opt.ok_or_else(|| serde::de::Error::custom("invalid pallas::Base"))
    }
}

/// Serde support for `pallas::Scalar` (Fq).
pub mod scalar {
    use super::*;
    use pasta_curves::pallas;

    pub fn serialize<S: serde::Serializer>(val: &pallas::Scalar, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&val.to_repr())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<pallas::Scalar, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes for pallas::Scalar"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let opt: Option<pallas::Scalar> = pallas::Scalar::from_repr(arr).into();
        opt.ok_or_else(|| serde::de::Error::custom("invalid pallas::Scalar"))
    }
}

/// Serde support for `[pallas::Base; N]` arrays via Vec.
pub mod base_array {
    use super::*;
    use pasta_curves::pallas;

    pub fn serialize<S: serde::Serializer, const N: usize>(
        arr: &[pallas::Base; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(N))?;
        for elem in arr {
            seq.serialize_element(&elem.to_repr())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[pallas::Base; N], D::Error> {
        // Deserialize as Vec<[u8; 32]> instead of Vec<Vec<u8>> to bound the
        // allocation per element to exactly 32 bytes, preventing an attacker
        // from supplying arbitrarily large inner byte arrays.
        let vecs: Vec<[u8; 32]> = serde::Deserialize::deserialize(d)?;
        if vecs.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} elements, got {}",
                N,
                vecs.len()
            )));
        }
        let mut result = [pallas::Base::zero(); N];
        for (i, arr) in vecs.iter().enumerate() {
            let opt: Option<pallas::Base> = pallas::Base::from_repr(*arr).into();
            result[i] = opt.ok_or_else(|| serde::de::Error::custom("invalid pallas::Base"))?;
        }
        Ok(result)
    }
}

/// Serde support for `Vec<pallas::Base>`.
pub mod base_vec {
    use super::*;
    use pasta_curves::pallas;

    pub fn serialize<S: serde::Serializer>(
        vec: &[pallas::Base],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(vec.len()))?;
        for elem in vec {
            seq.serialize_element(&elem.to_repr())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<pallas::Base>, D::Error> {
        let vecs: Vec<[u8; 32]> = serde::Deserialize::deserialize(d)?;
        let mut result = Vec::with_capacity(vecs.len());
        for arr in &vecs {
            let opt: Option<pallas::Base> = pallas::Base::from_repr(*arr).into();
            result.push(opt.ok_or_else(|| serde::de::Error::custom("invalid pallas::Base"))?);
        }
        Ok(result)
    }
}
