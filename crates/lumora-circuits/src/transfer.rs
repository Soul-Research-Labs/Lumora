//! Private Transfer Circuit — the core ZK proof for LUMORA.
//!
//! A 2-input-2-output private transfer. The circuit proves:
//!
//! 1. **Merkle membership**: Each input note's commitment exists in the tree.
//! 2. **Ownership**: The prover knows the spending key for each input note.
//! 3. **Value conservation**: sum(input values) == sum(output values) + fee.
//! 4. **Nullifier correctness**: Each nullifier is correctly derived.
//! 5. **Output well-formedness**: Output commitments are correctly computed.
//!
//! # Public Inputs (instance)
//!
//! | Index | Field             |
//! |-------|-------------------|
//! | 0     | Merkle root       |
//! | 1     | Nullifier 0       |
//! | 2     | Nullifier 1       |
//! | 3     | Output commit 0   |
//! | 4     | Output commit 1   |
//! | 5     | Fee               |
//!
//! # Private Inputs (witness / advice)
//!
//! For each input note (×2):
//! - spending_key (scalar as base field)
//! - value
//! - asset
//! - randomness (as base field)
//! - commitment (computed)
//! - Merkle path siblings [DEPTH]
//! - Merkle path index
//!
//! For each output note (×2):
//! - owner (public key as base field)
//! - value
//! - asset
//! - randomness (as base field)

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::pallas;

use crate::gadgets::poseidon_chip::PoseidonChipConfig;
use crate::gadgets::range_check::RangeCheckConfig;
use lumora_tree::DEPTH;

/// Number of input notes in a transfer.
pub const NUM_INPUTS: usize = 2;
/// Number of output notes in a transfer.
pub const NUM_OUTPUTS: usize = 2;
/// Total public inputs: 1 root + NUM_INPUTS nullifiers + NUM_OUTPUTS commitments + 1 fee.
pub const NUM_PUBLIC_INPUTS: usize = 1 + NUM_INPUTS + NUM_OUTPUTS + 1;

/// Witness data for one input note.
#[derive(Clone, Debug)]
pub struct InputNoteWitness {
    pub spending_key: Value<pallas::Base>,
    pub value: Value<pallas::Base>,
    pub asset: Value<pallas::Base>,
    pub randomness: Value<pallas::Base>,
    /// The note's commitment (will be verified inside the circuit).
    pub commitment: Value<pallas::Base>,
    /// Merkle path siblings from leaf to root.
    pub merkle_path: [Value<pallas::Base>; DEPTH],
    /// Leaf index in the tree.
    pub merkle_index: Value<u64>,
    /// Domain separation: chain_id (V2 nullifiers). `None` for V1.
    pub domain_chain_id: Option<Value<pallas::Base>>,
    /// Domain separation: app_id (V2 nullifiers). `None` for V1.
    pub domain_app_id: Option<Value<pallas::Base>>,
}

/// Witness data for one output note.
#[derive(Clone, Debug)]
pub struct OutputNoteWitness {
    pub owner: Value<pallas::Base>,
    pub value: Value<pallas::Base>,
    pub asset: Value<pallas::Base>,
    pub randomness: Value<pallas::Base>,
}

/// The private transfer circuit.
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    pub inputs: [InputNoteWitness; NUM_INPUTS],
    pub outputs: [OutputNoteWitness; NUM_OUTPUTS],
    /// Transaction fee (public input).
    pub fee: Value<pallas::Base>,
}

/// Circuit configuration — columns and chip configs.
#[derive(Clone, Debug)]
pub struct TransferConfig {
    /// Advice columns for general witness assignment.
    pub advice: [Column<Advice>; 4],
    /// Instance column for public inputs.
    pub instance: Column<Instance>,
    /// Fixed columns for Poseidon round constants.
    pub fixed: [Column<Fixed>; 6],
    /// Poseidon chip configuration.
    pub poseidon_config: PoseidonChipConfig,
    /// Range check chip (constrains values to u64).
    pub range_check_config: RangeCheckConfig,
    /// Selector for Merkle conditional swap gate.
    pub swap_selector: Selector,
    /// Selector for running-sum accumulation gate (advice[0]_next = advice[0]_cur + advice[1]_cur).
    pub sum_selector: Selector,
    /// Selector for inline addition gate (advice[3]_cur = advice[0]_cur + advice[1]_cur).
    pub add_selector: Selector,
    /// Selector for multiplication gate (advice[2]_cur = advice[0]_cur * advice[1]_cur).
    pub mul_selector: Selector,
    /// Selector for subtraction gate (advice[2]_cur = advice[0]_cur - advice[1]_cur).
    pub sub_selector: Selector,
}

impl Circuit<pallas::Base> for TransferCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: std::array::from_fn(|_| InputNoteWitness {
                spending_key: Value::unknown(),
                value: Value::unknown(),
                asset: Value::unknown(),
                randomness: Value::unknown(),
                commitment: Value::unknown(),
                merkle_path: [Value::unknown(); DEPTH],
                merkle_index: Value::unknown(),
                domain_chain_id: None,
                domain_app_id: None,
            }),
            outputs: std::array::from_fn(|_| OutputNoteWitness {
                owner: Value::unknown(),
                value: Value::unknown(),
                asset: Value::unknown(),
                randomness: Value::unknown(),
            }),
            fee: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Allocate columns.
        let advice: [Column<Advice>; 4] = std::array::from_fn(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);
            col
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let fixed: [Column<Fixed>; 6] = std::array::from_fn(|_| meta.fixed_column());

        // Enable one fixed column as a constant column (required by Pow5Chip).
        meta.enable_constant(fixed[3]);

        // Configure Poseidon chip using first 3 advice columns + 1 partial sbox column.
        let poseidon_config = PoseidonChipConfig::configure(
            meta,
            [advice[0], advice[1], advice[2]],
            advice[3],
            [fixed[0], fixed[1], fixed[2]],
            [fixed[3], fixed[4], fixed[5]],
        );

        // Configure range check chip (reuses two advice columns).
        let range_check_config = RangeCheckConfig::configure(
            meta,
            advice[0], // bits
            advice[1], // running_sum
        );

        // Selector for Merkle conditional swap.
        // Row layout:
        //   cur row:  advice[0]=current, advice[1]=sibling, advice[2]=bit
        //   next row: advice[0]=left,    advice[1]=right
        // Constraints:
        //   bit*(1-bit) == 0
        //   left  == current + bit*(sibling - current)
        //   right == sibling + bit*(current - sibling)
        let swap_selector = meta.selector();
        meta.create_gate("merkle_swap", |meta| {
            let s = meta.query_selector(swap_selector);
            let cur = meta.query_advice(advice[0], Rotation::cur());
            let sib = meta.query_advice(advice[1], Rotation::cur());
            let bit = meta.query_advice(advice[2], Rotation::cur());
            let left = meta.query_advice(advice[0], Rotation::next());
            let right = meta.query_advice(advice[1], Rotation::next());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::one());

            let boolean = bit.clone() * (one - bit.clone());
            let left_check = left - cur.clone() - bit.clone() * (sib.clone() - cur.clone());
            let right_check = right - sib.clone() - bit * (cur - sib);

            halo2_proofs::plonk::Constraints::with_selector(
                s,
                [("boolean", boolean), ("left", left_check), ("right", right_check)],
            )
        });

        // Selector for running-sum accumulation.
        // Row layout:
        //   cur row:  advice[0]=sum_i, advice[1]=v_{i+1}
        //   next row: advice[0]=sum_{i+1}
        // Constraint: sum_{i+1} == sum_i + v_{i+1}
        let sum_selector = meta.selector();
        meta.create_gate("sum_accumulate", |meta| {
            let s = meta.query_selector(sum_selector);
            let sum_cur = meta.query_advice(advice[0], Rotation::cur());
            let v = meta.query_advice(advice[1], Rotation::cur());
            let sum_next = meta.query_advice(advice[0], Rotation::next());

            halo2_proofs::plonk::Constraints::with_selector(
                s,
                [("sum", sum_next - sum_cur - v)],
            )
        });

        // Selector for inline addition.
        // Row layout:
        //   cur row: advice[0]=a, advice[1]=b, advice[3]=c
        // Constraint: c == a + b
        let add_selector = meta.selector();
        meta.create_gate("addition", |meta| {
            let s = meta.query_selector(add_selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[3], Rotation::cur());

            halo2_proofs::plonk::Constraints::with_selector(
                s,
                [("add", c - a - b)],
            )
        });

        // Selector for multiplication.
        // Row layout:
        //   cur row: advice[0]=a, advice[1]=b, advice[2]=c
        // Constraint: c == a * b
        let mul_selector = meta.selector();
        meta.create_gate("multiplication", |meta| {
            let s = meta.query_selector(mul_selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());

            halo2_proofs::plonk::Constraints::with_selector(
                s,
                [("mul", c - a * b)],
            )
        });

        // Selector for subtraction.
        // Row layout:
        //   cur row: advice[0]=a, advice[1]=b, advice[2]=c
        // Constraint: c == a - b
        let sub_selector = meta.selector();
        meta.create_gate("subtraction", |meta| {
            let s = meta.query_selector(sub_selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());

            halo2_proofs::plonk::Constraints::with_selector(
                s,
                [("sub", c - a + b)],
            )
        });

        TransferConfig {
            advice,
            instance,
            fixed,
            poseidon_config,
            range_check_config,
            swap_selector,
            sum_selector,
            add_selector,
            mul_selector,
            sub_selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // === Phase 1: Assign private witnesses ===

        let mut input_values: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();
        let mut input_nullifiers: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();
        let mut input_roots: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();

        for (i, input) in self.inputs.iter().enumerate() {
            let (value_cell, nullifier_cell, root_cell) = synthesize_input(
                &config,
                layouter.namespace(|| format!("input_{}", i)),
                input,
                i,
            )?;
            input_values.push(value_cell);
            input_nullifiers.push(nullifier_cell);
            input_roots.push(root_cell);
        }

        let mut output_values: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();
        let mut output_commitments: Vec<AssignedCell<pallas::Base, pallas::Base>> = Vec::new();

        for (i, output) in self.outputs.iter().enumerate() {
            let (value_cell, commitment_cell) = synthesize_output(
                &config,
                layouter.namespace(|| format!("output_{}", i)),
                output,
                i,
            )?;
            output_values.push(value_cell);
            output_commitments.push(commitment_cell);
        }

        // === Phase 1b: Range-check all values to u64 ===
        for (i, v) in input_values.iter().enumerate() {
            config.range_check_config.range_check_u64(
                layouter.namespace(|| format!("range_check_input_{}", i)),
                v,
            )?;
        }
        for (i, v) in output_values.iter().enumerate() {
            config.range_check_config.range_check_u64(
                layouter.namespace(|| format!("range_check_output_{}", i)),
                v,
            )?;
        }

        // === Phase 2: Value conservation ===
        // sum(input_values) == sum(output_values) + fee
        //
        // We compute input_sum and output_sum, assign fee, then constrain
        // input_sum == output_sum + fee.
        let input_sum = sum_values(
            &config,
            layouter.namespace(|| "input_sum"),
            &input_values,
        )?;
        let output_sum = sum_values(
            &config,
            layouter.namespace(|| "output_sum"),
            &output_values,
        )?;

        // Assign fee witness.
        let fee_cell = layouter.assign_region(
            || "assign fee",
            |mut region| {
                region.assign_advice(|| "fee", config.advice[0], 0, || self.fee)
            },
        )?;

        // Range-check fee to u64.
        config.range_check_config.range_check_u64(
            layouter.namespace(|| "range_check_fee"),
            &fee_cell,
        )?;

        // rhs = output_sum + fee
        let rhs = layouter.assign_region(
            || "value conservation",
            |mut region| {
                config.add_selector.enable(&mut region, 0)?;

                let out = output_sum.copy_advice(|| "output_sum", &mut region, config.advice[0], 0)?;
                let fee = fee_cell.copy_advice(|| "fee", &mut region, config.advice[1], 0)?;
                let inp = input_sum.copy_advice(|| "input_sum", &mut region, config.advice[2], 0)?;

                let rhs_val = out.value().zip(fee.value()).map(|(o, f)| *o + *f);
                let rhs = region.assign_advice(
                    || "output_sum + fee",
                    config.advice[3],
                    0,
                    || rhs_val,
                )?;

                // Constrain input_sum == rhs (= output_sum + fee)
                region.constrain_equal(inp.cell(), rhs.cell())?;
                Ok(rhs)
            },
        )?;

        // Keep rhs alive to prevent optimizer dropping it.
        let _ = rhs;

        // === Phase 3: Constrain public inputs ===

        // All input roots must equal the single public Merkle root.
        for root_cell in input_roots.iter() {
            layouter.constrain_instance(
                root_cell.cell(),
                config.instance,
                0, // Instance row 0 = Merkle root
            )?;
        }

        // Nullifiers exposed as public inputs.
        for (i, nf) in input_nullifiers.iter().enumerate() {
            layouter.constrain_instance(
                nf.cell(),
                config.instance,
                1 + i, // Instance rows 1, 2 = nullifiers
            )?;
        }

        // Output commitments exposed as public inputs.
        for (i, cm) in output_commitments.iter().enumerate() {
            layouter.constrain_instance(
                cm.cell(),
                config.instance,
                1 + NUM_INPUTS + i, // Instance rows 3, 4 = output commitments
            )?;
        }

        // Fee exposed as public input.
        layouter.constrain_instance(
            fee_cell.cell(),
            config.instance,
            1 + NUM_INPUTS + NUM_OUTPUTS, // Instance row 5 = fee
        )?;

        Ok(())
    }
}

/// Synthesize one input note: verify commitment, Merkle path, and derive nullifier.
///
/// Shared between TransferCircuit and WithdrawCircuit.
#[allow(clippy::type_complexity)]
pub(crate) fn synthesize_input(
    config: &TransferConfig,
    mut layouter: impl Layouter<pallas::Base>,
    input: &InputNoteWitness,
    _idx: usize,
) -> Result<
    (
        AssignedCell<pallas::Base, pallas::Base>, // value
        AssignedCell<pallas::Base, pallas::Base>, // nullifier
        AssignedCell<pallas::Base, pallas::Base>, // computed root
    ),
    Error,
> {
    // Assign witness cells.
    let (sk_cell, value_cell, asset_cell, randomness_cell, commitment_cell, path_cells, index_bits) =
        layouter.assign_region(
            || "input note witness",
            |mut region| {
                let sk = region.assign_advice(
                    || "spending_key",
                    config.advice[0],
                    0,
                    || input.spending_key,
                )?;
                let value = region.assign_advice(
                    || "value",
                    config.advice[1],
                    0,
                    || input.value,
                )?;
                let asset = region.assign_advice(
                    || "asset",
                    config.advice[2],
                    0,
                    || input.asset,
                )?;
                let randomness = region.assign_advice(
                    || "randomness",
                    config.advice[3],
                    0,
                    || input.randomness,
                )?;
                let commitment = region.assign_advice(
                    || "commitment",
                    config.advice[0],
                    1,
                    || input.commitment,
                )?;

                // Assign Merkle path siblings.
                let mut path_cells = Vec::with_capacity(DEPTH);
                for (j, sibling) in input.merkle_path.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("path_{}", j),
                        config.advice[(j + 1) % 4],
                        2 + j / 4,
                        || *sibling,
                    )?;
                    path_cells.push(cell);
                }

                // Assign index bits (for Merkle path direction).
                let mut idx_bits = Vec::with_capacity(DEPTH);
                for j in 0..DEPTH {
                    let bit = input.merkle_index.map(|idx| {
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

                Ok((sk, value, asset, randomness, commitment, path_cells, idx_bits))
            },
        )?;

    // --- Verify note commitment ---
    let inner_hash = config.poseidon_config.hash_two(
        layouter.namespace(|| "hash(sk, value)"),
        sk_cell.clone(),
        value_cell.clone(),
    )?;
    let content_hash = config.poseidon_config.hash_two(
        layouter.namespace(|| "hash(inner, asset)"),
        inner_hash,
        asset_cell.clone(),
    )?;
    let computed_commitment = config.poseidon_config.hash_two(
        layouter.namespace(|| "commitment = hash(content, randomness)"),
        content_hash.clone(),
        randomness_cell.clone(),
    )?;

    // Constrain computed_commitment == provided commitment.
    layouter.assign_region(
        || "verify commitment",
        |mut region| {
            computed_commitment.copy_advice(|| "computed", &mut region, config.advice[0], 0)?;
            commitment_cell.copy_advice(|| "provided", &mut region, config.advice[1], 0)?;
            region.constrain_equal(computed_commitment.cell(), commitment_cell.cell())
        },
    )?;

    // --- Verify Merkle path ---
    let root_cell = verify_merkle_path(
        config,
        layouter.namespace(|| "merkle path"),
        &computed_commitment,
        &path_cells,
        &index_bits,
    )?;

    // --- Derive nullifier ---
    // V2 domain-separated: hash_two(hash_two(sk, cm), hash_two(chain_id, app_id))
    // V1 legacy: hash_two(sk, cm)
    let nullifier_cell = if let (Some(chain_id_val), Some(app_id_val)) =
        (&input.domain_chain_id, &input.domain_app_id)
    {
        let (chain_id_cell, app_id_cell) = layouter.assign_region(
            || "domain fields",
            |mut region| {
                let cid = region.assign_advice(
                    || "chain_id",
                    config.advice[0],
                    0,
                    || *chain_id_val,
                )?;
                let aid = region.assign_advice(
                    || "app_id",
                    config.advice[1],
                    0,
                    || *app_id_val,
                )?;
                Ok((cid, aid))
            },
        )?;
        let left = config.poseidon_config.hash_two(
            layouter.namespace(|| "nf_left = hash(sk, cm)"),
            sk_cell.clone(),
            computed_commitment.clone(),
        )?;
        let right = config.poseidon_config.hash_two(
            layouter.namespace(|| "nf_right = hash(chain_id, app_id)"),
            chain_id_cell,
            app_id_cell,
        )?;
        config.poseidon_config.hash_two(
            layouter.namespace(|| "nullifier_v2 = hash(left, right)"),
            left,
            right,
        )?
    } else {
        config.poseidon_config.hash_two(
            layouter.namespace(|| "nullifier"),
            sk_cell.clone(),
            computed_commitment.clone(),
        )?
    };

    Ok((value_cell, nullifier_cell, root_cell))
}

/// Synthesize one output note: compute commitment.
///
/// Shared between TransferCircuit and WithdrawCircuit.
#[allow(clippy::type_complexity)]
pub(crate) fn synthesize_output(
    config: &TransferConfig,
    mut layouter: impl Layouter<pallas::Base>,
    output: &OutputNoteWitness,
    _idx: usize,
) -> Result<
    (
        AssignedCell<pallas::Base, pallas::Base>, // value
        AssignedCell<pallas::Base, pallas::Base>, // commitment
    ),
    Error,
> {
    let (owner_cell, value_cell, asset_cell, randomness_cell) = layouter.assign_region(
        || "output note witness",
        |mut region| {
            let owner = region.assign_advice(|| "owner", config.advice[0], 0, || output.owner)?;
            let value = region.assign_advice(|| "value", config.advice[1], 0, || output.value)?;
            let asset = region.assign_advice(|| "asset", config.advice[2], 0, || output.asset)?;
            let randomness =
                region.assign_advice(|| "randomness", config.advice[3], 0, || output.randomness)?;
            Ok((owner, value, asset, randomness))
        },
    )?;

    let inner = config.poseidon_config.hash_two(
        layouter.namespace(|| "out hash(owner, value)"),
        owner_cell,
        value_cell.clone(),
    )?;
    let content = config.poseidon_config.hash_two(
        layouter.namespace(|| "out hash(inner, asset)"),
        inner,
        asset_cell,
    )?;
    let commitment = config.poseidon_config.hash_two(
        layouter.namespace(|| "out commitment"),
        content,
        randomness_cell,
    )?;

    Ok((value_cell, commitment))
}

/// Verify a Merkle authentication path inside the circuit.
pub(crate) fn verify_merkle_path(
    config: &TransferConfig,
    mut layouter: impl Layouter<pallas::Base>,
    leaf: &AssignedCell<pallas::Base, pallas::Base>,
    siblings: &[AssignedCell<pallas::Base, pallas::Base>],
    index_bits: &[AssignedCell<pallas::Base, pallas::Base>],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let mut current = leaf.clone();

    for i in 0..DEPTH {
        let sibling = &siblings[i];
        let bit = &index_bits[i];

        let (left, right) = layouter.assign_region(
            || format!("merkle_swap_{}", i),
            |mut region| {
                config.swap_selector.enable(&mut region, 0)?;

                let cur = current.copy_advice(|| "current", &mut region, config.advice[0], 0)?;
                let sib = sibling.copy_advice(|| "sibling", &mut region, config.advice[1], 0)?;
                let b = bit.copy_advice(|| "bit", &mut region, config.advice[2], 0)?;

                let left_val = cur.value().zip(sib.value()).zip(b.value()).map(
                    |((c, s), b)| *c + *b * (*s - *c),
                );
                let left = region.assign_advice(|| "left", config.advice[0], 1, || left_val)?;

                let right_val = cur.value().zip(sib.value()).zip(b.value()).map(
                    |((c, s), b)| *s + *b * (*c - *s),
                );
                let right = region.assign_advice(|| "right", config.advice[1], 1, || right_val)?;

                Ok((left, right))
            },
        )?;

        current = config.poseidon_config.hash_two(
            layouter.namespace(|| format!("merkle_hash_{}", i)),
            left,
            right,
        )?;
    }

    Ok(current)
}

/// Sum a slice of value cells.
pub(crate) fn sum_values(
    config: &TransferConfig,
    mut layouter: impl Layouter<pallas::Base>,
    values: &[AssignedCell<pallas::Base, pallas::Base>],
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "sum values",
        |mut region| {
            let mut sum = values[0].copy_advice(|| "v0", &mut region, config.advice[0], 0)?;

            for (i, v) in values[1..].iter().enumerate() {
                config.sum_selector.enable(&mut region, i)?;

                let vi = v.copy_advice(
                    || format!("v{}", i + 1),
                    &mut region,
                    config.advice[1],
                    i,
                )?;
                let new_sum_val = sum.value().zip(vi.value()).map(|(a, b)| *a + *b);
                sum = region.assign_advice(
                    || format!("sum_{}", i + 1),
                    config.advice[0],
                    i + 1,
                    || new_sum_val,
                )?;
            }

            Ok(sum)
        },
    )
}

/// Build a `TransferCircuit` from concrete native values.
///
/// This is the bridge between `lumora-note` / `lumora-tree` types and the circuit.
#[allow(clippy::type_complexity)]
pub fn build_transfer_circuit(
    input_notes: &[(
        pallas::Base, // spending_key as base field
        u64,          // value
        u64,          // asset
        pallas::Base, // randomness as base field
        pallas::Base, // commitment
        [pallas::Base; DEPTH], // merkle path siblings
        u64,          // merkle index
    )],
    output_notes: &[(
        pallas::Base, // owner (pubkey field)
        u64,          // value
        u64,          // asset
        pallas::Base, // randomness as base field
    )],
    fee: u64,
) -> TransferCircuit {
    assert_eq!(input_notes.len(), NUM_INPUTS);
    assert_eq!(output_notes.len(), NUM_OUTPUTS);

    let inputs = std::array::from_fn(|i| {
        let (sk, value, asset, randomness, commitment, path, index) = &input_notes[i];
        InputNoteWitness {
            spending_key: Value::known(*sk),
            value: Value::known(pallas::Base::from(*value)),
            asset: Value::known(pallas::Base::from(*asset)),
            randomness: Value::known(*randomness),
            commitment: Value::known(*commitment),
            merkle_path: std::array::from_fn(|j| Value::known(path[j])),
            merkle_index: Value::known(*index),
            domain_chain_id: None,
            domain_app_id: None,
        }
    });

    let outputs = std::array::from_fn(|i| {
        let (owner, value, asset, randomness) = &output_notes[i];
        OutputNoteWitness {
            owner: Value::known(*owner),
            value: Value::known(pallas::Base::from(*value)),
            asset: Value::known(pallas::Base::from(*asset)),
            randomness: Value::known(*randomness),
        }
    });

    TransferCircuit { inputs, outputs, fee: Value::known(pallas::Base::from(fee)) }
}

/// Compute the public inputs vector for a transfer.
///
/// Order: [merkle_root, nullifier_0, nullifier_1, output_commitment_0, output_commitment_1, fee]
pub fn transfer_public_inputs(
    merkle_root: pallas::Base,
    nullifiers: &[pallas::Base; NUM_INPUTS],
    output_commitments: &[pallas::Base; NUM_OUTPUTS],
    fee: u64,
) -> Vec<pallas::Base> {
    let mut pi = Vec::with_capacity(NUM_PUBLIC_INPUTS);
    pi.push(merkle_root);
    pi.extend_from_slice(nullifiers);
    pi.extend_from_slice(output_commitments);
    pi.push(pallas::Base::from(fee));
    pi
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use lumora_primitives::poseidon;

    /// Helper: compute a note commitment natively (matching the in-circuit computation).
    /// commitment = hash(hash(hash(owner, value), asset), randomness)
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

    /// Helper: compute a nullifier natively.
    fn native_nullifier(sk: pallas::Base, commitment: pallas::Base) -> pallas::Base {
        poseidon::hash_two(sk, commitment)
    }

    /// Helper: compute merkle root from leaf, path, and index (native).
    fn native_merkle_root(
        leaf: pallas::Base,
        path: &[pallas::Base; DEPTH],
        index: u64,
    ) -> pallas::Base {
        let mut current = leaf;
        let mut idx = index;
        for sibling in path.iter() {
            let (left, right) = if idx & 1 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = poseidon::hash_two(left, right);
            idx >>= 1;
        }
        current
    }

    #[test]
    fn test_valid_transfer() {
        // Two input notes, two output notes with matching values.
        let sk = pallas::Base::from(42u64);
        let asset = 0u64;

        // Input 0: value 70
        let r_in0 = pallas::Base::from(111u64);
        let cm_in0 = native_commitment(sk, 70, asset, r_in0);

        // Input 1: value 30
        let r_in1 = pallas::Base::from(222u64);
        let cm_in1 = native_commitment(sk, 30, asset, r_in1);

        // Build a trivial Merkle tree with these two leaves at index 0 and 1.
        // For a depth-32 tree with 2 leaves, most siblings are zero-subtree hashes.
        let zero_hashes = {
            let mut z = [pallas::Base::zero(); DEPTH + 1];
            for i in 1..=DEPTH {
                z[i] = poseidon::hash_two(z[i - 1], z[i - 1]);
            }
            z
        };

        // Path for leaf at index 0: sibling at level 0 = cm_in1, rest are zero subtrees.
        let mut path0 = [pallas::Base::zero(); DEPTH];
        path0[0] = cm_in1;
        path0[1..DEPTH].copy_from_slice(&zero_hashes[1..DEPTH]);

        // Path for leaf at index 1: sibling at level 0 = cm_in0, rest are zero subtrees.
        let mut path1 = [pallas::Base::zero(); DEPTH];
        path1[0] = cm_in0;
        path1[1..DEPTH].copy_from_slice(&zero_hashes[1..DEPTH]);

        // Compute the shared root.
        let root0 = native_merkle_root(cm_in0, &path0, 0);
        let root1 = native_merkle_root(cm_in1, &path1, 1);
        assert_eq!(root0, root1, "Both leaves must produce the same root");
        let merkle_root = root0;

        // Nullifiers.
        let nf0 = native_nullifier(sk, cm_in0);
        let nf1 = native_nullifier(sk, cm_in1);

        // Output notes: 60 and 40 (70 + 30 = 60 + 40 = 100).
        let recipient = pallas::Base::from(99u64);
        let r_out0 = pallas::Base::from(333u64);
        let r_out1 = pallas::Base::from(444u64);
        let cm_out0 = native_commitment(recipient, 60, asset, r_out0);
        let cm_out1 = native_commitment(recipient, 40, asset, r_out1);

        // Build the circuit.
        let circuit = build_transfer_circuit(
            &[
                (sk, 70, asset, r_in0, cm_in0, path0, 0),
                (sk, 30, asset, r_in1, cm_in1, path1, 1),
            ],
            &[
                (recipient, 60, asset, r_out0),
                (recipient, 40, asset, r_out1),
            ],
            0, // fee = 0
        );

        let public_inputs = transfer_public_inputs(
            merkle_root,
            &[nf0, nf1],
            &[cm_out0, cm_out1],
            0, // fee = 0
        );

        // Run with MockProver. k=13 gives 2^13 rows which should be sufficient.
        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    /// Helper: set up a standard 2-leaf tree and return everything needed for
    /// a transfer circuit test (inputs, outputs, root, nullifiers, etc.).
    fn standard_test_setup() -> (
        pallas::Base, // sk
        u64,          // asset
        pallas::Base, // merkle_root
        pallas::Base, // nf0
        pallas::Base, // nf1
        pallas::Base, // cm_in0
        pallas::Base, // cm_in1
        [pallas::Base; DEPTH], // path0
        [pallas::Base; DEPTH], // path1
        pallas::Base, // r_in0
        pallas::Base, // r_in1
    ) {
        let sk = pallas::Base::from(42u64);
        let asset = 0u64;
        let r_in0 = pallas::Base::from(111u64);
        let cm_in0 = native_commitment(sk, 70, asset, r_in0);
        let r_in1 = pallas::Base::from(222u64);
        let cm_in1 = native_commitment(sk, 30, asset, r_in1);

        let zero_hashes = {
            let mut z = [pallas::Base::zero(); DEPTH + 1];
            for i in 1..=DEPTH { z[i] = poseidon::hash_two(z[i - 1], z[i - 1]); }
            z
        };
        let mut path0 = [pallas::Base::zero(); DEPTH];
        path0[0] = cm_in1;
        path0[1..DEPTH].copy_from_slice(&zero_hashes[1..DEPTH]);
        let mut path1 = [pallas::Base::zero(); DEPTH];
        path1[0] = cm_in0;
        path1[1..DEPTH].copy_from_slice(&zero_hashes[1..DEPTH]);

        let merkle_root = native_merkle_root(cm_in0, &path0, 0);
        let nf0 = native_nullifier(sk, cm_in0);
        let nf1 = native_nullifier(sk, cm_in1);
        (sk, asset, merkle_root, nf0, nf1, cm_in0, cm_in1, path0, path1, r_in0, r_in1)
    }

    #[test]
    fn test_value_conservation_violation_rejected() {
        // Inputs: 70 + 30 = 100. Outputs: 60 + 50 = 110 (overspend by 10).
        let (sk, asset, merkle_root, nf0, nf1, cm_in0, cm_in1, path0, path1, r_in0, r_in1) =
            standard_test_setup();

        let recipient = pallas::Base::from(99u64);
        let r_out0 = pallas::Base::from(333u64);
        let r_out1 = pallas::Base::from(444u64);
        let cm_out0 = native_commitment(recipient, 60, asset, r_out0);
        let cm_out1 = native_commitment(recipient, 50, asset, r_out1); // 50 instead of 40

        let circuit = build_transfer_circuit(
            &[
                (sk, 70, asset, r_in0, cm_in0, path0, 0),
                (sk, 30, asset, r_in1, cm_in1, path1, 1),
            ],
            &[
                (recipient, 60, asset, r_out0),
                (recipient, 50, asset, r_out1), // violated
            ],
            0,
        );

        let public_inputs = transfer_public_inputs(
            merkle_root, &[nf0, nf1], &[cm_out0, cm_out1], 0,
        );
        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        // Value conservation constraint must fail.
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_wrong_commitment_witness_rejected() {
        // Use wrong randomness for input commitment → Merkle path won't match.
        let (sk, asset, merkle_root, _nf0, nf1, _cm_in0, cm_in1, path0, path1, _r_in0, r_in1) =
            standard_test_setup();

        // Use wrong randomness for input 0
        let wrong_r = pallas::Base::from(9999u64);
        let wrong_cm = native_commitment(sk, 70, asset, wrong_r);

        let recipient = pallas::Base::from(99u64);
        let r_out0 = pallas::Base::from(333u64);
        let r_out1 = pallas::Base::from(444u64);
        let cm_out0 = native_commitment(recipient, 60, asset, r_out0);
        let cm_out1 = native_commitment(recipient, 40, asset, r_out1);

        let circuit = build_transfer_circuit(
            &[
                (sk, 70, asset, wrong_r, wrong_cm, path0, 0), // wrong commitment
                (sk, 30, asset, r_in1, cm_in1, path1, 1),
            ],
            &[
                (recipient, 60, asset, r_out0),
                (recipient, 40, asset, r_out1),
            ],
            0,
        );

        // Public inputs still expect the real nullifier & root
        let wrong_nf0 = native_nullifier(sk, wrong_cm);
        let public_inputs = transfer_public_inputs(
            merkle_root, &[wrong_nf0, nf1], &[cm_out0, cm_out1], 0,
        );
        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        // Merkle root constraint must fail (wrong leaf → wrong root).
        assert!(prover.verify().is_err());
    }
}
