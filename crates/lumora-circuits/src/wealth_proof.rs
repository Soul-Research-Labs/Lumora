//! #56 — ZK proof of wealth for compliance.
//!
//! Allows a user to prove that the total value of their unspent notes
//! exceeds a threshold without revealing exactly how much they own or
//! which notes they control. This is useful for regulatory compliance
//! scenarios (e.g., proof of reserves, accredited-investor checks).
//!
//! The proof is a Halo2 IPA range statement: `sum(note_values) >= threshold`
//! where note values, ownership, and Merkle paths are private.
//!
//! # Public Inputs
//!
//! | Index | Field     |
//! |-------|-----------|
//! | 0     | Merkle root |
//! | 1     | Threshold |
//! | 2     | Asset     |
//!
//! # Private Inputs (per note, up to MAX_WEALTH_NOTES)
//!
//! - spending_key (owner)
//! - value
//! - asset
//! - randomness
//! - Merkle path siblings \[DEPTH\]
//! - Merkle path index

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{self, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};

use crate::gadgets::poseidon_chip::PoseidonChipConfig;
use crate::gadgets::range_check::RangeCheckConfig;
use crate::transfer::{TransferConfig, verify_merkle_path};
use lumora_tree::DEPTH;

/// A wealth claim: "I own at least `threshold` units of `asset`."
#[derive(Clone, Debug)]
pub struct WealthClaim {
    /// The asset being claimed.
    pub asset: pallas::Base,
    /// Minimum total value the prover claims to own.
    pub threshold: u64,
}

/// Private witness backing a wealth claim.
#[derive(Clone, Debug)]
pub struct WealthWitness {
    /// Values of the owned notes.
    pub note_values: Vec<u64>,
    /// Merkle root attesting that each note is in the tree.
    pub merkle_root: pallas::Base,
    /// Note commitments (one per note).
    pub commitments: Vec<pallas::Base>,
    /// Spending keys (owner fields) for each note.
    pub spending_keys: Vec<pallas::Base>,
    /// Randomness for each note commitment.
    pub randomness: Vec<pallas::Base>,
    /// Asset id for each note.
    pub assets: Vec<u64>,
    /// Merkle path siblings for each note.
    pub merkle_paths: Vec<[pallas::Base; DEPTH]>,
    /// Merkle leaf index for each note.
    pub merkle_indices: Vec<u64>,
}

impl WealthWitness {
    /// Total value across all owned notes.
    pub fn total_value(&self) -> u64 {
        self.note_values.iter().sum()
    }

    /// Check that the witness satisfies the claim.
    pub fn satisfies(&self, claim: &WealthClaim) -> bool {
        self.total_value() >= claim.threshold
    }
}

/// Result of a wealth proof generation.
#[derive(Clone, Debug)]
pub struct WealthProof {
    /// The claim being proven.
    pub claim: WealthClaim,
    /// Halo2 IPA proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Number of notes used in the proof.
    pub note_count: usize,
}

/// Errors from wealth proof operations.
#[derive(Debug)]
pub enum WealthProofError {
    /// Witness does not satisfy the claim.
    InsufficientWealth { have: u64, need: u64 },
    /// Too many notes for the circuit.
    TooManyNotes { count: usize, max: usize },
    /// Proof generation failed.
    ProveFailed(String),
}

impl std::fmt::Display for WealthProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientWealth { have, need } => {
                write!(f, "insufficient wealth: have {have}, need {need}")
            }
            Self::TooManyNotes { count, max } => {
                write!(f, "too many notes: {count} > max {max}")
            }
            Self::ProveFailed(e) => write!(f, "wealth proof failed: {e}"),
        }
    }
}

impl std::error::Error for WealthProofError {}

/// Maximum notes that can be included in a single wealth proof.
pub const MAX_WEALTH_NOTES: usize = 16;

/// Number of public inputs: merkle_root + threshold + asset.
pub const NUM_WEALTH_PUBLIC_INPUTS: usize = 3;

/// K parameter for the wealth proof circuit (2^K rows).
/// Needs to be large enough for MAX_WEALTH_NOTES Merkle verifications + range checks.
pub const WEALTH_K: u32 = 15;

// ───────────────────────────────────────────────────────────────────
// Witness data for one note in the wealth circuit
// ───────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct WealthNoteWitness {
    spending_key: Value<pallas::Base>,
    value: Value<pallas::Base>,
    asset: Value<pallas::Base>,
    randomness: Value<pallas::Base>,
    commitment: Value<pallas::Base>,
    merkle_path: [Value<pallas::Base>; DEPTH],
    merkle_index: Value<u64>,
    /// Whether this note slot is active (1) or padding (0).
    active: Value<pallas::Base>,
}

impl WealthNoteWitness {
    fn padding() -> Self {
        use lumora_primitives::poseidon;
        // Compute the deterministic commitment for a zero-value note:
        // commitment = hash(hash(hash(0, 0), 0), 0)
        let zero = pallas::Base::zero();
        let inner = poseidon::hash_two(zero, zero);
        let content = poseidon::hash_two(inner, zero);
        let cm = poseidon::hash_two(content, zero);

        Self {
            spending_key: Value::known(zero),
            value: Value::known(zero),
            asset: Value::known(zero),
            randomness: Value::known(zero),
            commitment: Value::known(cm),
            merkle_path: [Value::known(zero); DEPTH],
            merkle_index: Value::known(0),
            active: Value::known(zero),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// WealthCircuit
// ───────────────────────────────────────────────────────────────────

/// Halo2 circuit proving `sum(active note values) >= threshold`.
#[derive(Clone, Debug)]
pub struct WealthCircuit {
    notes: Vec<WealthNoteWitness>,
    threshold: Value<pallas::Base>,
    asset: Value<pallas::Base>,
}

impl WealthCircuit {
    /// Build a wealth circuit from native witness data.
    pub fn build(claim: &WealthClaim, witness: &WealthWitness) -> Self {
        let n = witness.note_values.len();
        let mut notes = Vec::with_capacity(MAX_WEALTH_NOTES);

        for i in 0..MAX_WEALTH_NOTES {
            if i < n {
                notes.push(WealthNoteWitness {
                    spending_key: Value::known(witness.spending_keys[i]),
                    value: Value::known(pallas::Base::from(witness.note_values[i])),
                    asset: Value::known(pallas::Base::from(witness.assets[i])),
                    randomness: Value::known(witness.randomness[i]),
                    commitment: Value::known(witness.commitments[i]),
                    merkle_path: std::array::from_fn(|j| {
                        Value::known(witness.merkle_paths[i][j])
                    }),
                    merkle_index: Value::known(witness.merkle_indices[i]),
                    active: Value::known(pallas::Base::one()),
                });
            } else {
                notes.push(WealthNoteWitness::padding());
            }
        }

        Self {
            notes,
            threshold: Value::known(pallas::Base::from(claim.threshold)),
            asset: Value::known(claim.asset),
        }
    }
}

impl Circuit<pallas::Base> for WealthCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            notes: (0..MAX_WEALTH_NOTES)
                .map(|_| WealthNoteWitness {
                    spending_key: Value::unknown(),
                    value: Value::unknown(),
                    asset: Value::unknown(),
                    randomness: Value::unknown(),
                    commitment: Value::unknown(),
                    merkle_path: [Value::unknown(); DEPTH],
                    merkle_index: Value::unknown(),
                    active: Value::unknown(),
                })
                .collect(),
            threshold: Value::unknown(),
            asset: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Reuse the full transfer circuit configuration including all gates.
        <crate::transfer::TransferCircuit as Circuit<pallas::Base>>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // For each note slot, verify commitment + Merkle membership,
        // and collect (value * active) for summation.
        let mut weighted_values: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();
        let mut roots: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();

        for (i, note) in self.notes.iter().enumerate() {
            // Assign note witness.
            let (sk, value, asset, randomness, commitment, path_cells, idx_bits, active) =
                layouter.assign_region(
                    || format!("wealth_note_{}", i),
                    |mut region| {
                        let sk = region.assign_advice(
                            || "sk", config.advice[0], 0, || note.spending_key,
                        )?;
                        let value = region.assign_advice(
                            || "value", config.advice[1], 0, || note.value,
                        )?;
                        let asset = region.assign_advice(
                            || "asset", config.advice[2], 0, || note.asset,
                        )?;
                        let randomness = region.assign_advice(
                            || "randomness", config.advice[3], 0, || note.randomness,
                        )?;
                        let commitment = region.assign_advice(
                            || "commitment", config.advice[0], 1, || note.commitment,
                        )?;
                        let active = region.assign_advice(
                            || "active", config.advice[1], 1, || note.active,
                        )?;

                        let mut path_cells = Vec::with_capacity(DEPTH);
                        for (j, sibling) in note.merkle_path.iter().enumerate() {
                            let cell = region.assign_advice(
                                || format!("path_{}", j),
                                config.advice[(j + 1) % 4],
                                2 + j / 4,
                                || *sibling,
                            )?;
                            path_cells.push(cell);
                        }

                        let mut idx_bits = Vec::with_capacity(DEPTH);
                        for j in 0..DEPTH {
                            let bit = note.merkle_index.map(|idx| {
                                if (idx >> j) & 1 == 1 {
                                    pallas::Base::one()
                                } else {
                                    pallas::Base::zero()
                                }
                            });
                            let cell = region.assign_advice(
                                || format!("idx_bit_{}", j),
                                config.advice[j % 4],
                                2 + DEPTH / 4 + 1 + j / 4,
                                || bit,
                            )?;
                            idx_bits.push(cell);
                        }

                        Ok((sk, value, asset, randomness, commitment, path_cells, idx_bits, active))
                    },
                )?;

            // Range-check the value to u64.
            config.range_check_config.range_check_u64(
                layouter.namespace(|| format!("range_val_{}", i)),
                &value,
            )?;

            // Verify note commitment = hash(hash(hash(sk, value), asset), randomness).
            let inner = config.poseidon_config.hash_two(
                layouter.namespace(|| format!("hash_sk_val_{}", i)),
                sk, value.clone(),
            )?;
            let content = config.poseidon_config.hash_two(
                layouter.namespace(|| format!("hash_inner_asset_{}", i)),
                inner, asset,
            )?;
            let computed_cm = config.poseidon_config.hash_two(
                layouter.namespace(|| format!("hash_cm_{}", i)),
                content, randomness,
            )?;

            // Constrain computed_cm == provided commitment.
            layouter.assign_region(
                || format!("verify_cm_{}", i),
                |mut region| {
                    computed_cm.copy_advice(|| "computed", &mut region, config.advice[0], 0)?;
                    commitment.copy_advice(|| "provided", &mut region, config.advice[1], 0)?;
                    region.constrain_equal(computed_cm.cell(), commitment.cell())
                },
            )?;

            // Verify Merkle path for this note.
            let root = verify_merkle_path(
                &config,
                layouter.namespace(|| format!("merkle_{}", i)),
                &computed_cm,
                &path_cells,
                &idx_bits,
            )?;
            roots.push(root);

            // Compute weighted value = value * active (0 for padding slots).
            let wv = layouter.assign_region(
                || format!("weighted_val_{}", i),
                |mut region| {
                    config.mul_selector.enable(&mut region, 0)?;

                    let v = value.copy_advice(|| "val", &mut region, config.advice[0], 0)?;
                    let a = active.copy_advice(|| "active", &mut region, config.advice[1], 0)?;
                    let prod = v.value().zip(a.value()).map(|(v, a)| *v * *a);
                    region.assign_advice(|| "v*a", config.advice[2], 0, || prod)
                },
            )?;
            weighted_values.push(wv);

            // Boolean constraint: active ∈ {0, 1} via active² == active.
            layouter.assign_region(
                || format!("bool_active_{}", i),
                |mut region| {
                    config.mul_selector.enable(&mut region, 0)?;

                    let a0 = active.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                    let a1 = active.copy_advice(|| "a_dup", &mut region, config.advice[1], 0)?;
                    let sq = a0.value().zip(a1.value()).map(|(x, y)| *x * *y);
                    let sq_cell = region.assign_advice(|| "a²", config.advice[2], 0, || sq)?;
                    // a² == a implies a ∈ {0,1}
                    region.constrain_equal(sq_cell.cell(), a0.cell())
                },
            )?;
        }

        // Sum all weighted values.
        let total = layouter.assign_region(
            || "sum_wealth",
            |mut region| {
                let mut sum = weighted_values[0].copy_advice(
                    || "wv0", &mut region, config.advice[0], 0,
                )?;
                for (i, wv) in weighted_values[1..].iter().enumerate() {
                    config.sum_selector.enable(&mut region, i)?;

                    let vi = wv.copy_advice(
                        || format!("wv{}", i + 1), &mut region, config.advice[1], i,
                    )?;
                    let new_sum = sum.value().zip(vi.value()).map(|(a, b)| *a + *b);
                    sum = region.assign_advice(
                        || format!("sum_{}", i + 1), config.advice[0], i + 1, || new_sum,
                    )?;
                }
                Ok(sum)
            },
        )?;

        // Assign threshold.
        let threshold_cell = layouter.assign_region(
            || "threshold",
            |mut region| {
                region.assign_advice(|| "threshold", config.advice[0], 0, || self.threshold)
            },
        )?;

        // Compute surplus = total - threshold and range-check it to u64
        // (proves total >= threshold without revealing total).
        let surplus = layouter.assign_region(
            || "surplus",
            |mut region| {
                config.sub_selector.enable(&mut region, 0)?;

                let t = total.copy_advice(|| "total", &mut region, config.advice[0], 0)?;
                let th = threshold_cell.copy_advice(
                    || "threshold", &mut region, config.advice[1], 0,
                )?;
                let diff = t.value().zip(th.value()).map(|(t, th)| *t - *th);
                region.assign_advice(|| "surplus", config.advice[2], 0, || diff)
            },
        )?;

        // Range-check surplus to u64 — proves sum >= threshold.
        config.range_check_config.range_check_u64(
            layouter.namespace(|| "range_surplus"),
            &surplus,
        )?;

        // Assign asset.
        let asset_cell = layouter.assign_region(
            || "asset_pi",
            |mut region| {
                region.assign_advice(|| "asset", config.advice[0], 0, || self.asset)
            },
        )?;

        // Expose public inputs: merkle_root (index 0), threshold (1), asset (2).
        // For active notes, root must match the public root.
        // For padding notes (active=0), no root constraint needed.

        // Assign a dedicated root cell for the public input.
        // We take the root from note 0 (which is always active for valid proofs).
        layouter.constrain_instance(roots[0].cell(), config.instance, 0)?;

        // For subsequent notes: constrain active * (root_i - root_0) == 0.
        // When active=1, root_i must equal root_0.
        // When active=0 (padding), the constraint is trivially satisfied.
        for i in 1..roots.len() {
            // Step 1: diff = root_i - root_0
            let diff_cell = layouter.assign_region(
                || format!("cond_root_diff_{}", i),
                |mut region| {
                    config.sub_selector.enable(&mut region, 0)?;

                    let ri = roots[i].copy_advice(
                        || "root_i", &mut region, config.advice[0], 0,
                    )?;
                    let r0 = roots[0].copy_advice(
                        || "root_0", &mut region, config.advice[1], 0,
                    )?;
                    let diff = ri.value().zip(r0.value()).map(|(a, b)| *a - *b);
                    region.assign_advice(
                        || "diff", config.advice[2], 0, || diff,
                    )
                },
            )?;

            // Step 2: prod = active * diff, constrain prod == 0
            layouter.assign_region(
                || format!("cond_root_mul_{}", i),
                |mut region| {
                    config.mul_selector.enable(&mut region, 0)?;

                    let active_i = self.notes[i].active;
                    let active_cell = region.assign_advice(
                        || "active_i", config.advice[0], 0, || active_i,
                    )?;
                    let d = diff_cell.copy_advice(
                        || "diff", &mut region, config.advice[1], 0,
                    )?;
                    let prod = active_cell.value().zip(d.value())
                        .map(|(a, d)| *a * *d);
                    let prod_cell = region.assign_advice(
                        || "prod", config.advice[2], 0, || prod,
                    )?;

                    // Constrain product == 0 via a zero constant.
                    let zero = region.assign_advice_from_constant(
                        || "zero", config.advice[3], 0, pallas::Base::zero(),
                    )?;
                    region.constrain_equal(prod_cell.cell(), zero.cell())
                },
            )?;
        }

        layouter.constrain_instance(threshold_cell.cell(), config.instance, 1)?;
        layouter.constrain_instance(asset_cell.cell(), config.instance, 2)?;

        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────
// Proving / Verification API
// ───────────────────────────────────────────────────────────────────

/// Prover/verifier parameter bundle for wealth proofs.
#[derive(Clone)]
pub struct WealthProverParams {
    pub params: Params<vesta::Affine>,
    pub pk: halo2_proofs::plonk::ProvingKey<vesta::Affine>,
}

/// Verifier parameter bundle for wealth proofs.
#[derive(Clone)]
pub struct WealthVerifierParams {
    pub params: Params<vesta::Affine>,
    pub vk: halo2_proofs::plonk::VerifyingKey<vesta::Affine>,
}

/// Generate proving and verifying keys for the wealth circuit.
pub fn setup_wealth() -> Result<(WealthProverParams, WealthVerifierParams), WealthProofError> {
    let params: Params<vesta::Affine> = Params::new(WEALTH_K);
    let empty = WealthCircuit {
        notes: (0..MAX_WEALTH_NOTES).map(|_| WealthNoteWitness::padding()).collect(),
        threshold: Value::unknown(),
        asset: Value::unknown(),
    };
    let vk = halo2_proofs::plonk::keygen_vk(&params, &empty)
        .map_err(|e| WealthProofError::ProveFailed(format!("keygen_vk: {e:?}")))?;
    let pk = halo2_proofs::plonk::keygen_pk(&params, vk.clone(), &empty)
        .map_err(|e| WealthProofError::ProveFailed(format!("keygen_pk: {e:?}")))?;

    Ok((
        WealthProverParams { params: params.clone(), pk },
        WealthVerifierParams { params, vk },
    ))
}

/// Compute the public inputs vector for a wealth proof.
pub fn wealth_public_inputs(
    merkle_root: pallas::Base,
    threshold: u64,
    asset: pallas::Base,
) -> Vec<pallas::Base> {
    vec![merkle_root, pallas::Base::from(threshold), asset]
}

/// Generate a wealth proof using real Halo2 IPA proving.
pub fn prove_wealth(
    claim: &WealthClaim,
    witness: &WealthWitness,
) -> Result<WealthProof, WealthProofError> {
    if witness.note_values.len() > MAX_WEALTH_NOTES {
        return Err(WealthProofError::TooManyNotes {
            count: witness.note_values.len(),
            max: MAX_WEALTH_NOTES,
        });
    }

    let total = witness.total_value();
    if total < claim.threshold {
        return Err(WealthProofError::InsufficientWealth {
            have: total,
            need: claim.threshold,
        });
    }

    let circuit = WealthCircuit::build(claim, witness);
    let public_inputs = wealth_public_inputs(witness.merkle_root, claim.threshold, claim.asset);

    let (prover_params, _) = setup_wealth()?;

    let mut transcript = Blake2bWrite::<Vec<u8>, vesta::Affine, Challenge255<_>>::init(vec![]);
    halo2_proofs::plonk::create_proof(
        &prover_params.params,
        &prover_params.pk,
        &[circuit],
        &[&[&public_inputs]],
        &mut rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|e| WealthProofError::ProveFailed(format!("{e:?}")))?;

    let proof_bytes = transcript.finalize();

    Ok(WealthProof {
        claim: claim.clone(),
        proof_bytes,
        note_count: witness.note_values.len(),
    })
}

/// Verify a wealth proof using real Halo2 IPA verification.
pub fn verify_wealth(
    proof: &WealthProof,
    merkle_root: pallas::Base,
    verifier: &WealthVerifierParams,
) -> bool {
    let public_inputs = wealth_public_inputs(
        merkle_root,
        proof.claim.threshold,
        proof.claim.asset,
    );
    let strategy = halo2_proofs::plonk::SingleVerifier::new(&verifier.params);
    let mut transcript =
        Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof.proof_bytes[..]);

    plonk::verify_proof(
        &verifier.params,
        &verifier.vk,
        strategy,
        &[&[&public_inputs]],
        &mut transcript,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use lumora_primitives::poseidon;
    use lumora_tree::IncrementalMerkleTree;

    /// Compute native commitment matching in-circuit logic.
    fn native_commitment(
        owner: pallas::Base,
        value: u64,
        asset: u64,
        randomness: pallas::Base,
    ) -> pallas::Base {
        let inner = poseidon::hash_two(owner, pallas::Base::from(value));
        let content = poseidon::hash_two(inner, pallas::Base::from(asset));
        poseidon::hash_two(content, randomness)
    }

    fn build_test_witness(values: &[u64]) -> (WealthClaim, WealthWitness) {
        let sk = pallas::Base::from(42u64);
        let asset = 0u64;
        let threshold: u64 = values.iter().sum::<u64>() / 2; // claim half the total

        let mut tree = IncrementalMerkleTree::new();
        let mut commitments = Vec::new();
        let mut randomness = Vec::new();
        let mut paths = Vec::new();
        let mut indices = Vec::new();

        for (i, &val) in values.iter().enumerate() {
            let r = pallas::Base::from(100 + i as u64);
            let cm = native_commitment(sk, val, asset, r);
            let idx = tree.insert(cm);
            commitments.push(cm);
            randomness.push(r);
            indices.push(idx);
        }

        // Get paths after all insertions.
        for &idx in &indices {
            let mp = tree.witness(idx).expect("valid index");
            paths.push(mp.siblings);
        }

        let root = tree.root();

        let claim = WealthClaim {
            asset: pallas::Base::from(asset),
            threshold,
        };
        let witness = WealthWitness {
            note_values: values.to_vec(),
            merkle_root: root,
            commitments,
            spending_keys: vec![sk; values.len()],
            randomness,
            assets: vec![asset; values.len()],
            merkle_paths: paths,
            merkle_indices: indices,
        };

        (claim, witness)
    }

    #[test]
    fn wealth_circuit_mock_prover() {
        let (claim, witness) = build_test_witness(&[300, 200]);
        let circuit = WealthCircuit::build(&claim, &witness);
        let pi = wealth_public_inputs(witness.merkle_root, claim.threshold, claim.asset);
        let prover = MockProver::run(WEALTH_K, &circuit, vec![pi]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn wealth_circuit_mock_prover_single_note() {
        let (claim, witness) = build_test_witness(&[500]);
        let circuit = WealthCircuit::build(&claim, &witness);
        let pi = wealth_public_inputs(witness.merkle_root, claim.threshold, claim.asset);
        let prover = MockProver::run(WEALTH_K, &circuit, vec![pi]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn wealth_proof_insufficient() {
        let (mut claim, witness) = build_test_witness(&[50, 50]);
        claim.threshold = 200; // more than total
        let err = prove_wealth(&claim, &witness).unwrap_err();
        assert!(matches!(err, WealthProofError::InsufficientWealth { .. }));
    }

    #[test]
    fn wealth_proof_too_many_notes() {
        let values = vec![100; MAX_WEALTH_NOTES + 1];
        let (claim, witness) = build_test_witness(&values);
        let err = prove_wealth(&claim, &witness).unwrap_err();
        assert!(matches!(err, WealthProofError::TooManyNotes { .. }));
    }

    #[test]
    fn witness_satisfies() {
        let (claim, witness) = build_test_witness(&[300, 250]);
        assert!(witness.satisfies(&claim));

        let big_claim = WealthClaim {
            asset: claim.asset,
            threshold: 1000,
        };
        assert!(!witness.satisfies(&big_claim));
    }
}
