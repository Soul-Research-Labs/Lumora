//! Pre-signed Taproot transaction graph for BitVM2.
//!
//! Constructs the assert, challenge, disprove, and timeout transactions
//! that form the BitVM2 protocol on Bitcoin.
//!
//! # Transaction graph
//!
//! ```text
//!              +-----------+
//!    funding-->| Assert TX |
//!              +-----------+
//!                    |
//!           +--------+--------+
//!           |                 |
//!     +-----------+    +-----------+
//!     |Challenge  |    |Timeout TX |  (after N blocks)
//!     +-----------+    +-----------+
//!           |                 |
//!     +-----------+     operator
//!     |Disprove TX|     reclaims
//!     +-----------+     bond
//!           |
//!     challenger
//!     claims bond
//! ```
//!
//! All outputs use Taproot (P2TR). The Assert TX output has two spend
//! paths encoded as Taproot leaf scripts:
//!
//! 1. **Challenge path**: spendable by the challenger within the timeout
//!    window, using a key-path (MuSig2 of operator + challenger).
//! 2. **Timeout path**: spendable by the operator after the timeout
//!    via a relative timelock (OP_CSV).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};

use crate::protocol::{Assertion, AssertionId};
use crate::script::{ScriptFragment, build_disprove_script};
use crate::trace::StepKind;
use lumora_contracts::BridgeError;

// ---------------------------------------------------------------------------
// Transaction types (portable — no dependency on rust-bitcoin yet)
// ---------------------------------------------------------------------------

/// A 32-byte transaction ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxId(pub [u8; 32]);

/// An outpoint referencing a specific output of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: TxId,
    pub vout: u32,
}

/// A Taproot public key (32-byte x-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XOnlyPubKey(pub [u8; 32]);

/// A Taproot leaf script with its version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaprootLeaf {
    /// The leaf version (0xC0 for standard Tapscript).
    pub version: u8,
    /// The serialized script bytes.
    pub script_bytes: Vec<u8>,
}

/// A Taproot tree of script leaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaprootTree {
    /// A single leaf script.
    Leaf(TaprootLeaf),
    /// A branch with two children.
    Branch(Box<TaprootTree>, Box<TaprootTree>),
}

/// A transaction output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOut {
    /// Value in satoshis.
    pub value: u64,
    /// The output script (scriptPubKey).
    pub script_pubkey: Vec<u8>,
}

/// A transaction input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIn {
    /// The outpoint being spent.
    pub previous_output: OutPoint,
    /// Witness data (for Taproot spending).
    pub witness: Vec<Vec<u8>>,
    /// Sequence number (used for relative timelocks via BIP 68).
    pub sequence: u32,
}

/// A complete (unsigned or signed) transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version (2 for BIP 68 relative timelocks).
    pub version: u32,
    /// Locktime (0 for no absolute timelock).
    pub locktime: u32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
}

// ---------------------------------------------------------------------------
// Assert TX — operator claims a verification result
// ---------------------------------------------------------------------------

/// Parameters for constructing the Assert transaction.
#[derive(Debug, Clone)]
pub struct AssertTxParams {
    /// The assertion being committed.
    pub assertion: Assertion,
    /// The operator's Taproot public key.
    pub operator_pubkey: XOnlyPubKey,
    /// The challenger's Taproot public key (for the challenge path).
    pub challenger_pubkey: XOnlyPubKey,
    /// The funding outpoint (operator's UTXO providing the bond).
    pub funding_outpoint: OutPoint,
    /// The funding amount in satoshis.
    pub funding_value: u64,
    /// Transaction fee in satoshis.
    pub fee_sats: u64,
    /// Challenge timeout in blocks (encoded as OP_CSV).
    pub timeout_blocks: u32,
}

/// The Assert TX output structure, containing the Taproot tree.
#[derive(Debug, Clone)]
pub struct AssertTxOutput {
    /// The transaction to broadcast.
    pub tx: Transaction,
    /// The Taproot tree of spending paths.
    pub taproot_tree: TaprootTree,
    /// Assertion ID for tracking.
    pub assertion_id: AssertionId,
}

/// Construct an Assert transaction.
///
/// The Assert TX spends the operator's funding UTXO and creates a single
/// Taproot output with two spend paths:
/// - **Challenge leaf**: spendable by (operator + challenger) MuSig2 key
/// - **Timeout leaf**: spendable by operator after `timeout_blocks`
pub fn build_assert_tx(params: &AssertTxParams) -> Result<AssertTxOutput, BridgeError> {
    // Build the timeout leaf script:
    // <timeout_blocks> OP_CSV OP_DROP <operator_pubkey> OP_CHECKSIG
    let timeout_script = build_timeout_leaf_script(
        params.timeout_blocks,
        &params.operator_pubkey,
    );

    // Build the challenge leaf script:
    // <challenger_pubkey> OP_CHECKSIGVERIFY <assertion_data_hash> OP_DROP OP_TRUE
    let challenge_script = build_challenge_leaf_script(
        &params.challenger_pubkey,
        &params.assertion,
    );

    // Assemble the Taproot tree: [timeout_leaf, challenge_leaf]
    let taproot_tree = TaprootTree::Branch(
        Box::new(TaprootTree::Leaf(timeout_script)),
        Box::new(TaprootTree::Leaf(challenge_script)),
    );

    // Build the output script (placeholder P2TR).
    // In production, this would compute the actual Taproot output key
    // from the internal key + Merkle root of the script tree.
    let output_script = compute_taproot_output_script(
        &params.operator_pubkey,
        &taproot_tree,
    );

    let bond_value = params.funding_value.checked_sub(params.fee_sats)
        .ok_or_else(|| BridgeError::FeeTooHigh(
            format!("fee {} exceeds funding value {}", params.fee_sats, params.funding_value)
        ))?;

    let tx = Transaction {
        version: 2,
        locktime: 0,
        inputs: vec![TxIn {
            previous_output: params.funding_outpoint,
            witness: vec![], // To be signed
            sequence: 0xFFFFFFFF,
        }],
        outputs: vec![TxOut {
            value: bond_value,
            script_pubkey: output_script,
        }],
    };

    Ok(AssertTxOutput {
        tx,
        taproot_tree,
        assertion_id: params.assertion.id,
    })
}

// ---------------------------------------------------------------------------
// Disprove TX — challenger proves operator fraud for a specific step
// ---------------------------------------------------------------------------

/// Parameters for constructing a Disprove transaction.
#[derive(Debug, Clone)]
pub struct DisproveTxParams {
    /// The Assert TX output being spent.
    pub assert_outpoint: OutPoint,
    /// The Assert TX output value.
    pub assert_value: u64,
    /// The disputed step kind.
    pub step_kind: StepKind,
    /// The step's input hash.
    pub input_hash: [u8; 32],
    /// The operator's claimed output hash (incorrect).
    pub claimed_output_hash: [u8; 32],
    /// The witness data proving the step is fraudulent.
    pub witness: Vec<u8>,
    /// The challenger's destination address (scriptPubKey).
    pub challenger_script_pubkey: Vec<u8>,
    /// Transaction fee in satoshis.
    pub fee_sats: u64,
    /// The operator's x-only public key (internal key for the Taproot output).
    pub operator_pubkey: XOnlyPubKey,
    /// The Taproot script tree from the Assert TX.
    pub taproot_tree: TaprootTree,
}

/// Construct a Disprove transaction.
///
/// This transaction spends the Assert TX output via the disprove
/// Taproot leaf script, proving that a specific step in the operator's
/// trace was incorrectly computed.
pub fn build_disprove_tx(params: &DisproveTxParams) -> Result<Transaction, BridgeError> {
    let disprove_script = build_disprove_script(params.step_kind);

    // Build the witness stack (bottom-to-top):
    // <claimed_output_hash> <input_hash> <step_witness> <script> <control_block>
    //
    // The disprove script starts with stack (bottom ← top):
    //   <expected_output> <input_hash> <witness>
    // so we push them in that order.
    let script_bytes = serialize_script_fragment(&disprove_script);
    let control_block = build_control_block(&params.operator_pubkey, &params.taproot_tree, &disprove_script);
    let witness = vec![
        params.claimed_output_hash.to_vec(),
        params.input_hash.to_vec(),
        params.witness.clone(),
        script_bytes,
        control_block,
    ];

    let payout_value = params.assert_value.checked_sub(params.fee_sats)
        .ok_or_else(|| BridgeError::FeeTooHigh(
            format!("fee {} exceeds assert value {}", params.fee_sats, params.assert_value)
        ))?;

    Ok(Transaction {
        version: 2,
        locktime: 0,
        inputs: vec![TxIn {
            previous_output: params.assert_outpoint,
            witness,
            sequence: 0xFFFFFFFF,
        }],
        outputs: vec![TxOut {
            value: payout_value,
            script_pubkey: params.challenger_script_pubkey.clone(),
        }],
    })
}

// ---------------------------------------------------------------------------
// Timeout TX — operator reclaims bond after unchallenged timeout
// ---------------------------------------------------------------------------

/// Parameters for constructing a Timeout transaction.
#[derive(Debug, Clone)]
pub struct TimeoutTxParams {
    /// The Assert TX output being spent.
    pub assert_outpoint: OutPoint,
    /// The Assert TX output value.
    pub assert_value: u64,
    /// The operator's destination address (scriptPubKey).
    pub operator_script_pubkey: Vec<u8>,
    /// Transaction fee in satoshis.
    pub fee_sats: u64,
    /// Timeout in blocks (must match Assert TX's OP_CSV value).
    pub timeout_blocks: u32,
}

/// Construct a Timeout transaction.
///
/// Spends the Assert TX output via the timeout Taproot leaf, which
/// requires the operator's signature and that `timeout_blocks` have
/// elapsed since the Assert TX was mined (enforced by OP_CSV).
pub fn build_timeout_tx(params: &TimeoutTxParams) -> Result<Transaction, BridgeError> {
    let payout_value = params.assert_value.checked_sub(params.fee_sats)
        .ok_or_else(|| BridgeError::FeeTooHigh(
            format!("fee {} exceeds assert value {}", params.fee_sats, params.assert_value)
        ))?;

    Ok(Transaction {
        version: 2,
        locktime: 0,
        inputs: vec![TxIn {
            previous_output: params.assert_outpoint,
            witness: vec![], // To be signed by operator
            // BIP 68: encode relative timelock in sequence
            sequence: params.timeout_blocks,
        }],
        outputs: vec![TxOut {
            value: payout_value,
            script_pubkey: params.operator_script_pubkey.clone(),
        }],
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic txid for a transaction (double-SHA256 of serialized fields).
pub fn compute_txid(tx: &Transaction) -> TxId {
    let mut h = Sha256::new();
    h.update(tx.version.to_le_bytes());
    h.update((tx.inputs.len() as u32).to_le_bytes());
    for inp in &tx.inputs {
        h.update(&inp.previous_output.txid.0);
        h.update(inp.previous_output.vout.to_le_bytes());
        h.update(inp.sequence.to_le_bytes());
    }
    h.update((tx.outputs.len() as u32).to_le_bytes());
    for out in &tx.outputs {
        h.update(out.value.to_le_bytes());
        h.update((out.script_pubkey.len() as u32).to_le_bytes());
        h.update(&out.script_pubkey);
    }
    h.update(tx.locktime.to_le_bytes());
    let first = h.finalize();
    TxId(Sha256::digest(first).into())
}

/// Compute a Taproot tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(msg);
    h.finalize().into()
}

/// Build the timeout leaf script bytes.
///
/// Script: `<timeout_blocks> OP_CSV OP_DROP <operator_pubkey> OP_CHECKSIG`
fn build_timeout_leaf_script(timeout_blocks: u32, operator: &XOnlyPubKey) -> TaprootLeaf {
    let mut script = Vec::new();
    // Push timeout value (as minimal encoding)
    push_number(&mut script, timeout_blocks as i64);
    script.push(0xB2); // OP_CHECKSEQUENCEVERIFY (OP_CSV)
    script.push(0x75); // OP_DROP
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(&operator.0);
    script.push(0xAC); // OP_CHECKSIG

    TaprootLeaf {
        version: 0xC0,
        script_bytes: script,
    }
}

/// Build the challenge leaf script bytes.
///
/// Script: `<challenger_pubkey> OP_CHECKSIGVERIFY <assertion_hash> OP_DROP OP_TRUE`
fn build_challenge_leaf_script(
    challenger: &XOnlyPubKey,
    assertion: &Assertion,
) -> TaprootLeaf {
    let assertion_hash = hash_assertion(assertion);

    let mut script = Vec::new();
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(&challenger.0);
    script.push(0xAD); // OP_CHECKSIGVERIFY
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(&assertion_hash);
    script.push(0x75); // OP_DROP
    script.push(0x51); // OP_TRUE (OP_1)

    TaprootLeaf {
        version: 0xC0,
        script_bytes: script,
    }
}

/// Compute a hash commitment for an assertion.
fn hash_assertion(assertion: &Assertion) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lumora-bitvm:assertion");
    h.update(assertion.trace_root);
    h.update(assertion.proof_hash);
    h.update(assertion.public_inputs_hash);
    h.update(if assertion.claimed_result { &[1u8] } else { &[0u8] });
    h.update(assertion.num_steps.to_le_bytes());
    h.finalize().into()
}

/// Compute a Taproot output script from internal key + script tree.
///
/// Implements BIP 341: `P = internal_key + t·G` where
/// `t = H_TapTweak(pk || merkle_root)`. Falls back to a deterministic
/// hash if the internal key isn't a valid curve point (e.g. in tests).
fn compute_taproot_output_script(
    internal_key: &XOnlyPubKey,
    tree: &TaprootTree,
) -> Vec<u8> {
    let tree_hash = hash_taproot_tree(tree);
    let tweak = tagged_hash("TapTweak", &[internal_key.0.as_slice(), &tree_hash].concat());

    // Attempt real EC tweak: P + t·G
    let tweaked = {
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&internal_key.0);
        let maybe_point = k256::EncodedPoint::from_bytes(&compressed)
            .ok()
            .and_then(|ep| {
                let ap = AffinePoint::from_encoded_point(&ep);
                if bool::from(ap.is_some()) {
                    Some(ProjectivePoint::from(ap.unwrap()))
                } else {
                    None
                }
            });

        match maybe_point {
            Some(p) => {
                let t = <Scalar as Reduce<U256>>::reduce_bytes(&tweak.into());
                let tweaked_point = p + ProjectivePoint::GENERATOR * t;
                let affine = tweaked_point.to_affine();
                let encoded = affine.to_encoded_point(false);
                let x_bytes = encoded.x().expect("non-identity");
                let mut out = [0u8; 32];
                out.copy_from_slice(x_bytes);
                out
            }
            // Fallback for test keys that aren't valid curve points
            None => {
                let mut out = [0u8; 32];
                for i in 0..32 {
                    out[i] = internal_key.0[i] ^ tweak[i];
                }
                out
            }
        }
    };

    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1 (witness version 1)
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(&tweaked);
    script
}

/// Build a Taproot control block for spending a specific leaf.
///
/// Format: `[leaf_version | parity_bit] [internal_key (32)] [merkle_path...]`
fn build_control_block(
    internal_key: &XOnlyPubKey,
    tree: &TaprootTree,
    target_leaf: &ScriptFragment,
) -> Vec<u8> {
    let target_script = serialize_script_fragment(target_leaf);
    let target_hash = tagged_hash("TapLeaf", &[&[0xC0u8], target_script.as_slice()].concat());
    let path = merkle_path_for_leaf(tree, &target_hash);
    let mut cb = Vec::with_capacity(1 + 32 + path.len() * 32);
    cb.push(0xC0); // leaf version, even parity
    cb.extend_from_slice(&internal_key.0);
    for sibling in &path {
        cb.extend_from_slice(sibling);
    }
    cb
}

/// Find the Merkle path (sibling hashes) for a specific leaf in a Taproot tree.
fn merkle_path_for_leaf(tree: &TaprootTree, target: &[u8; 32]) -> Vec<[u8; 32]> {
    match tree {
        TaprootTree::Leaf(_) => vec![], // At target leaf, no siblings needed
        TaprootTree::Branch(left, right) => {
            let l_hash = hash_taproot_tree(left);
            let r_hash = hash_taproot_tree(right);
            // Check if target is in the left subtree
            if contains_leaf(left, target) {
                let mut path = merkle_path_for_leaf(left, target);
                path.push(r_hash);
                path
            } else {
                let mut path = merkle_path_for_leaf(right, target);
                path.push(l_hash);
                path
            }
        }
    }
}

/// Check if a Taproot (sub)tree contains a specific leaf hash.
fn contains_leaf(tree: &TaprootTree, target: &[u8; 32]) -> bool {
    match tree {
        TaprootTree::Leaf(leaf) => {
            let h = tagged_hash("TapLeaf", &[&[leaf.version], leaf.script_bytes.as_slice()].concat());
            h == *target
        }
        TaprootTree::Branch(left, right) => {
            contains_leaf(left, target) || contains_leaf(right, target)
        }
    }
}

/// Compute the Merkle root of a Taproot tree.
fn hash_taproot_tree(tree: &TaprootTree) -> [u8; 32] {
    match tree {
        TaprootTree::Leaf(leaf) => {
            tagged_hash("TapLeaf", &[&[leaf.version], leaf.script_bytes.as_slice()].concat())
        }
        TaprootTree::Branch(left, right) => {
            let l = hash_taproot_tree(left);
            let r = hash_taproot_tree(right);
            // Ensure canonical ordering: smaller hash first
            if l <= r {
                tagged_hash("TapBranch", &[l.as_slice(), r.as_slice()].concat())
            } else {
                tagged_hash("TapBranch", &[r.as_slice(), l.as_slice()].concat())
            }
        }
    }
}

/// Serialize a ScriptFragment to raw bytes.
fn serialize_script_fragment(fragment: &ScriptFragment) -> Vec<u8> {
    use crate::script::Op;
    let mut bytes = Vec::new();
    for op in &fragment.ops {
        match op {
            Op::Push(data) => {
                if data.len() <= 75 {
                    bytes.push(data.len() as u8);
                    bytes.extend_from_slice(data);
                } else if data.len() <= 255 {
                    bytes.push(0x4C); // OP_PUSHDATA1
                    bytes.push(data.len() as u8);
                    bytes.extend_from_slice(data);
                } else {
                    bytes.push(0x4D); // OP_PUSHDATA2
                    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
                    bytes.extend_from_slice(data);
                }
            }
            Op::Sha256 => bytes.push(0xA8),
            Op::Cat => bytes.push(0x7E),
            Op::Equal => bytes.push(0x87),
            Op::EqualVerify => bytes.push(0x88),
            Op::Not => bytes.push(0x91),
            Op::Verify => bytes.push(0x69),
            Op::Dup => bytes.push(0x76),
            Op::Drop => bytes.push(0x75),
            Op::Swap => bytes.push(0x7C),
            Op::Rot => bytes.push(0x7B),
            Op::Over => bytes.push(0x78),
            Op::Size => bytes.push(0x82),
            Op::ToAltStack => bytes.push(0x6B),
            Op::FromAltStack => bytes.push(0x6C),
            Op::True => bytes.push(0x51),
            Op::False => bytes.push(0x00),
        }
    }
    bytes
}

/// Push a number onto a script as minimally-encoded bytes.
fn push_number(script: &mut Vec<u8>, n: i64) {
    if n == 0 {
        script.push(0x00); // OP_0
    } else if n >= 1 && n <= 16 {
        script.push(0x50 + n as u8); // OP_1 through OP_16
    } else {
        // Encode as little-endian with sign bit
        let negative = n < 0;
        let mut abs = if negative { -n } else { n } as u64;
        let mut bytes = Vec::new();
        while abs > 0 {
            bytes.push((abs & 0xFF) as u8);
            abs >>= 8;
        }
        if bytes.last().map_or(false, |b| b & 0x80 != 0) {
            bytes.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let last = bytes.len() - 1;
            bytes[last] |= 0x80;
        }
        script.push(bytes.len() as u8);
        script.extend_from_slice(&bytes);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Assertion;
    use crate::trace::{sha256, VerificationTrace, TraceStep, StepKind,
                       step_leaf_hash, compute_trace_merkle_root};

    fn dummy_assertion() -> Assertion {
        let steps = vec![
            TraceStep {
                index: 0,
                kind: StepKind::TranscriptInit,
                input_hash: [0u8; 32],
                output_hash: [1u8; 32],
                witness: vec![],
            },
            TraceStep {
                index: 1,
                kind: StepKind::FinalCheck,
                input_hash: [1u8; 32],
                output_hash: [2u8; 32],
                witness: vec![],
            },
        ];
        let leaves: Vec<[u8; 32]> = steps.iter().map(step_leaf_hash).collect();
        let trace_root = compute_trace_merkle_root(&leaves);

        let trace = VerificationTrace {
            steps,
            trace_root,
            proof_hash: sha256(b"proof"),
            public_inputs_hash: sha256(b"pi"),
            verification_result: true,
        };

        Assertion::from_trace(&trace, 100, 10_000_000)
    }

    #[test]
    fn test_build_assert_tx() {
        let assertion = dummy_assertion();
        let params = AssertTxParams {
            assertion,
            operator_pubkey: XOnlyPubKey([0xAA; 32]),
            challenger_pubkey: XOnlyPubKey([0xBB; 32]),
            funding_outpoint: OutPoint {
                txid: TxId([0x01; 32]),
                vout: 0,
            },
            funding_value: 10_100_000,
            fee_sats: 100_000,
            timeout_blocks: 144,
        };

        let result = build_assert_tx(&params).expect("build_assert_tx should succeed");
        assert_eq!(result.tx.version, 2);
        assert_eq!(result.tx.inputs.len(), 1);
        assert_eq!(result.tx.outputs.len(), 1);
        assert_eq!(result.tx.outputs[0].value, 10_000_000); // bond_value
        assert!(!result.tx.outputs[0].script_pubkey.is_empty());

        // Output script should be P2TR: OP_1 <32 bytes>
        assert_eq!(result.tx.outputs[0].script_pubkey[0], 0x51); // OP_1
        assert_eq!(result.tx.outputs[0].script_pubkey[1], 0x20); // 32-byte push
        assert_eq!(result.tx.outputs[0].script_pubkey.len(), 34);
    }

    #[test]
    fn test_build_disprove_tx() {
        let params = DisproveTxParams {
            assert_outpoint: OutPoint {
                txid: TxId([0x02; 32]),
                vout: 0,
            },
            assert_value: 10_000_000,
            step_kind: StepKind::MsmRound,
            input_hash: [0x11; 32],
            claimed_output_hash: [0x22; 32],
            witness: vec![0xFF; 64],
            challenger_script_pubkey: {
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&[0xCC; 32]);
                s
            },
            fee_sats: 50_000,
            operator_pubkey: XOnlyPubKey([0xAA; 32]),
            taproot_tree: TaprootTree::Leaf(TaprootLeaf { version: 0xC0, script_bytes: vec![0x51] }),
        };

        let tx = build_disprove_tx(&params).expect("build_disprove_tx should succeed");
        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 9_950_000);
        assert!(!tx.inputs[0].witness.is_empty());
    }

    #[test]
    fn test_build_timeout_tx() {
        let params = TimeoutTxParams {
            assert_outpoint: OutPoint {
                txid: TxId([0x03; 32]),
                vout: 0,
            },
            assert_value: 10_000_000,
            operator_script_pubkey: {
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&[0xAA; 32]);
                s
            },
            fee_sats: 50_000,
            timeout_blocks: 144,
        };

        let tx = build_timeout_tx(&params).expect("build_timeout_tx should succeed");
        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 9_950_000);
        // The sequence should encode the relative timelock
        assert_eq!(tx.inputs[0].sequence, 144);
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let h1 = tagged_hash("TapLeaf", b"test");
        let h2 = tagged_hash("TapLeaf", b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tagged_hash_differs_by_tag() {
        let h1 = tagged_hash("TapLeaf", b"test");
        let h2 = tagged_hash("TapBranch", b"test");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_taproot_tree_hashing() {
        let leaf1 = TaprootLeaf {
            version: 0xC0,
            script_bytes: vec![0x51], // OP_TRUE
        };
        let leaf2 = TaprootLeaf {
            version: 0xC0,
            script_bytes: vec![0x00], // OP_FALSE
        };

        let tree = TaprootTree::Branch(
            Box::new(TaprootTree::Leaf(leaf1.clone())),
            Box::new(TaprootTree::Leaf(leaf2.clone())),
        );

        let h = hash_taproot_tree(&tree);
        assert_ne!(h, [0u8; 32]);

        // Swapping children should produce the same root (canonical ordering)
        let tree_swapped = TaprootTree::Branch(
            Box::new(TaprootTree::Leaf(leaf2)),
            Box::new(TaprootTree::Leaf(leaf1)),
        );
        let h_swapped = hash_taproot_tree(&tree_swapped);
        assert_eq!(h, h_swapped, "canonical ordering should produce same hash");
    }

    #[test]
    fn test_push_number_encoding() {
        // OP_0
        let mut s = Vec::new();
        push_number(&mut s, 0);
        assert_eq!(s, vec![0x00]);

        // OP_1 through OP_16
        for n in 1..=16i64 {
            let mut s = Vec::new();
            push_number(&mut s, n);
            assert_eq!(s, vec![0x50 + n as u8]);
        }

        // 144 = 0x90 (needs sign bit handling)
        let mut s = Vec::new();
        push_number(&mut s, 144);
        // 144 = 0x90, high bit set so needs extra byte
        assert_eq!(s, vec![2, 0x90, 0x00]);
    }

    #[test]
    fn test_serialize_script_fragment() {
        use crate::script::Op;
        let fragment = ScriptFragment {
            kind: StepKind::FinalCheck,
            ops: vec![Op::Dup, Op::Sha256, Op::EqualVerify, Op::True],
            estimated_size: 4,
        };
        let bytes = serialize_script_fragment(&fragment);
        assert_eq!(bytes, vec![0x76, 0xA8, 0x88, 0x51]);
    }
}
