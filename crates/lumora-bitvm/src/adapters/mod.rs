//! Bitcoin ecosystem bridge adapters.
//!
//! Each adapter implements [`RollupBridge`](lumora_contracts::bridge::RollupBridge)
//! and optionally [`OnChainVerifier`](lumora_contracts::rollup::OnChainVerifier)
//! using the host chain's native RPC interface, generic over
//! [`RpcTransport`](lumora_contracts::rollup::RpcTransport).
//!
//! | Module | Chain / Protocol | Type |
//! |--------|-----------------|------|
//! | [`citrea`] | Citrea | ZK rollup on Bitcoin |
//! | [`bob`] | BOB (Build on Bitcoin) | Hybrid L2 (EVM + Bitcoin) |
//! | [`bitlayer`] | BitLayer | BitVM-native L2 |
//! | [`merlin`] | Merlin Chain | ZK rollup |
//! | [`bevm`] | BEVM | EVM-compatible L2 |
//! | [`babylon`] | Babylon | Bitcoin staking protocol |
//! | [`stacks`] | Stacks / sBTC | Smart contract L2 |
//! | [`rgb`] | RGB Protocol | Client-side validation |
//! | [`lightning`] | Lightning Network | Payment channels |
//! | [`liquid`] | Liquid Network | Federated sidechain |
//! | [`ark`] | Ark Protocol | Virtual UTXO layer |
//! | [`rooch`] | Rooch Network | MoveOS application layer |
//! | [`bison`] | Bison Labs | ZK-STARK rollup |

pub mod citrea;
pub mod bob;
pub mod bitlayer;
pub mod merlin;
pub mod bevm;
pub mod babylon;
pub mod stacks;
pub mod rgb;
pub mod lightning;
pub mod liquid;
pub mod ark;
pub mod rooch;
pub mod bison;

use ff::PrimeField;
use pasta_curves::pallas;
use sha2::{Digest, Sha256};

/// Encode a Pallas field element as a 64-char lowercase hex string (32-byte LE).
pub(crate) fn field_to_hex(f: &pallas::Base) -> String {
    hex::encode(f.to_repr())
}

/// Decode a 64-char hex string into a Pallas field element.
pub(crate) fn hex_to_field(h: &str) -> Result<pallas::Base, String> {
    let bytes = hex::decode(h).map_err(|e| format!("hex decode: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())?;
    Option::from(pallas::Base::from_repr(arr)).ok_or_else(|| "invalid field element".to_string())
}

/// SHA-256 hash of a byte slice.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
