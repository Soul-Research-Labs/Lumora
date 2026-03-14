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

/// Generate the common bridge struct, constructors, config accessor, and RPC
/// helper that every adapter shares verbatim.
///
/// # Usage
/// ```ignore
/// bridge_boilerplate!(MerlinBridge, MerlinConfig);
/// ```
macro_rules! bridge_boilerplate {
    ($bridge:ident, $config:ident) => {
        pub struct $bridge<T: RpcTransport = OfflineTransport> {
            config: $config,
            transport: T,
            next_id: std::cell::Cell<u64>,
        }

        impl $bridge<OfflineTransport> {
            pub fn new(config: $config) -> Self {
                Self {
                    config,
                    transport: OfflineTransport,
                    next_id: std::cell::Cell::new(1),
                }
            }
        }

        impl<T: RpcTransport> $bridge<T> {
            pub fn with_transport(config: $config, transport: T) -> Self {
                Self {
                    config,
                    transport,
                    next_id: std::cell::Cell::new(1),
                }
            }

            pub fn config(&self) -> &$config {
                &self.config
            }

            fn rpc_call(
                &self,
                method: &str,
                params: serde_json::Value,
            ) -> Result<serde_json::Value, BridgeError> {
                let id = self.next_id.get();
                self.next_id.set(id.wrapping_add(1));
                let req = JsonRpcRequest {
                    jsonrpc: "2.0",
                    id,
                    method: method.to_string(),
                    params,
                };
                let resp = self.transport.send(&self.config.rpc_url, &req)?;
                if let Some(err) = resp.error {
                    return Err(BridgeError::ConnectionError(format!(
                        "RPC error {}: {}",
                        err.code, err.message
                    )));
                }
                resp.result
                    .ok_or_else(|| {
                        BridgeError::ConnectionError("RPC response missing result".into())
                    })
            }
        }
    };
}

pub(crate) use bridge_boilerplate;

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

/// Parse a JSON array of remote nullifier roots, rejecting invalid entries
/// rather than silently substituting zero values.
pub(crate) fn parse_remote_nullifier_roots(
    entries: Vec<serde_json::Value>,
) -> Result<Vec<lumora_contracts::bridge::RemoteNullifierEpochRoot>, lumora_contracts::bridge::BridgeError> {
    entries
        .into_iter()
        .map(|e| {
            let chain_id = e["chain_id"]
                .as_u64()
                .ok_or_else(|| lumora_contracts::bridge::BridgeError::NullifierSyncFailed(
                    "missing or invalid chain_id".into(),
                ))?;
            let epoch_id = e["epoch_id"]
                .as_u64()
                .ok_or_else(|| lumora_contracts::bridge::BridgeError::NullifierSyncFailed(
                    "missing or invalid epoch_id".into(),
                ))?;
            let root_str = e["root"]
                .as_str()
                .ok_or_else(|| lumora_contracts::bridge::BridgeError::NullifierSyncFailed(
                    "missing root field".into(),
                ))?;
            let root = hex_to_field(root_str)
                .map_err(|e| lumora_contracts::bridge::BridgeError::NullifierSyncFailed(
                    format!("invalid root field element: {e}"),
                ))?;
            Ok(lumora_contracts::bridge::RemoteNullifierEpochRoot { chain_id, epoch_id, root })
        })
        .collect()
}

// ─── Mock transport for adapter tests ───────────────────────────────────

#[cfg(test)]
pub(crate) mod mock {
    use std::collections::HashMap;
    use lumora_contracts::bridge::BridgeError;
    use lumora_contracts::rollup::{JsonRpcRequest, JsonRpcResponse, RpcTransport};

    /// A configurable mock transport that returns predefined JSON responses
    /// keyed by RPC method name. Use this to test adapter logic without a
    /// real network endpoint.
    pub struct MockTransport {
        responses: HashMap<String, serde_json::Value>,
    }

    impl MockTransport {
        pub fn new() -> Self {
            Self { responses: HashMap::new() }
        }

        /// Register a canned response for a given RPC method.
        pub fn on(mut self, method: &str, response: serde_json::Value) -> Self {
            self.responses.insert(method.to_string(), response);
            self
        }
    }

    impl RpcTransport for MockTransport {
        fn send(&self, _url: &str, request: &JsonRpcRequest) -> Result<JsonRpcResponse, BridgeError> {
            let result = self.responses.get(&request.method).cloned();
            Ok(JsonRpcResponse {
                id: request.id,
                result,
                error: None,
            })
        }
    }
}
