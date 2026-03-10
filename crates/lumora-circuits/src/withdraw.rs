//! Withdrawal Circuit — ZK proof for unshielding funds from LUMORA.
//!
//! A variant of the transfer circuit where value can leave the pool.
//! The circuit proves:
//!
//! 1. **Merkle membership**: Each input note's commitment exists in the tree.
//! 2. **Ownership**: The prover knows the spending key for each input note.
//! 3. **Value conservation**: sum(input values) == sum(output values) + exit_value + fee.
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
//! | 5     | Exit value        |
//! | 6     | Fee               |

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::pallas;

use crate::transfer::{
    InputNoteWitness, OutputNoteWitness, TransferConfig,
    synthesize_input, synthesize_output, sum_values,
    NUM_INPUTS, NUM_OUTPUTS,
};
use lumora_tree::DEPTH;

/// Total public inputs: 1 root + 2 nullifiers + 2 commitments + 1 exit_value + 1 fee.
pub const NUM_WITHDRAW_PUBLIC_INPUTS: usize = 1 + NUM_INPUTS + NUM_OUTPUTS + 1 + 1;

/// The withdrawal circuit.
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    pub inputs: [InputNoteWitness; NUM_INPUTS],
    pub outputs: [OutputNoteWitness; NUM_OUTPUTS],
    /// The value leaving the pool (public input).
    pub exit_value: Value<pallas::Base>,
    /// Transaction fee (public input).
    pub fee: Value<pallas::Base>,
}

impl Circuit<pallas::Base> for WithdrawCircuit {
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
            exit_value: Value::unknown(),
            fee: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Reuse the same configuration as TransferCircuit.
        <crate::transfer::TransferCircuit as Circuit<pallas::Base>>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // === Phase 1: Assign private witnesses ===

        let mut input_values = Vec::new();
        let mut input_nullifiers = Vec::new();
        let mut input_roots = Vec::new();

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

        let mut output_values = Vec::new();
        let mut output_commitments = Vec::new();

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

        // === Phase 2: Value conservation with exit_value + fee ===
        // sum(input_values) == sum(output_values) + exit_value + fee

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

        // Assign exit_value and compute output_sum + exit_value.
        let exit_cell = layouter.assign_region(
            || "assign exit_value",
            |mut region| {
                region.assign_advice(
                    || "exit_value",
                    config.advice[0],
                    0,
                    || self.exit_value,
                )
            },
        )?;

        // Range-check exit_value to u64.
        config.range_check_config.range_check_u64(
            layouter.namespace(|| "range_check_exit_value"),
            &exit_cell,
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

        // rhs = output_sum + exit_value + fee
        let rhs = layouter.assign_region(
            || "value conservation (withdraw)",
            |mut region| {
                let out = output_sum.copy_advice(|| "output_sum", &mut region, config.advice[0], 0)?;
                let exit = exit_cell.copy_advice(|| "exit", &mut region, config.advice[1], 0)?;
                let fee = fee_cell.copy_advice(|| "fee", &mut region, config.advice[2], 0)?;

                // mid = output_sum + exit_value
                let mid_val = out.value().zip(exit.value()).map(|(o, e)| *o + *e);
                let mid = region.assign_advice(
                    || "output_sum + exit_value",
                    config.advice[3],
                    0,
                    || mid_val,
                )?;

                // rhs = mid + fee
                let rhs_val = mid.value().zip(fee.value()).map(|(m, f)| *m + *f);
                let rhs = region.assign_advice(
                    || "output_sum + exit_value + fee",
                    config.advice[0],
                    1,
                    || rhs_val,
                )?;

                // Constrain input_sum == rhs
                let inp = input_sum.copy_advice(|| "input_sum", &mut region, config.advice[1], 1)?;
                region.constrain_equal(inp.cell(), rhs.cell())?;
                Ok(rhs)
            },
        )?;

        // Keep rhs alive to prevent optimizer dropping it.
        let _ = rhs;

        // === Phase 3: Constrain public inputs ===

        // Instance row 0 = Merkle root.
        for root_cell in input_roots.iter() {
            layouter.constrain_instance(root_cell.cell(), config.instance, 0)?;
        }

        // Instance rows 1, 2 = nullifiers.
        for (i, nf) in input_nullifiers.iter().enumerate() {
            layouter.constrain_instance(nf.cell(), config.instance, 1 + i)?;
        }

        // Instance rows 3, 4 = output commitments.
        for (i, cm) in output_commitments.iter().enumerate() {
            layouter.constrain_instance(cm.cell(), config.instance, 1 + NUM_INPUTS + i)?;
        }

        // Instance row 5 = exit_value.
        layouter.constrain_instance(
            exit_cell.cell(),
            config.instance,
            1 + NUM_INPUTS + NUM_OUTPUTS,
        )?;

        // Instance row 6 = fee.
        layouter.constrain_instance(
            fee_cell.cell(),
            config.instance,
            1 + NUM_INPUTS + NUM_OUTPUTS + 1,
        )?;

        Ok(())
    }
}

/// Build a `WithdrawCircuit` from concrete native values.
#[allow(clippy::type_complexity)]
pub fn build_withdraw_circuit(
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
    exit_value: u64,
    fee: u64,
) -> WithdrawCircuit {
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

    WithdrawCircuit {
        inputs,
        outputs,
        exit_value: Value::known(pallas::Base::from(exit_value)),
        fee: Value::known(pallas::Base::from(fee)),
    }
}

/// Compute the public inputs vector for a withdrawal.
///
/// Order: [merkle_root, nf0, nf1, cm_out0, cm_out1, exit_value, fee]
pub fn withdraw_public_inputs(
    merkle_root: pallas::Base,
    nullifiers: &[pallas::Base; NUM_INPUTS],
    output_commitments: &[pallas::Base; NUM_OUTPUTS],
    exit_value: u64,
    fee: u64,
) -> Vec<pallas::Base> {
    let mut pi = Vec::with_capacity(NUM_WITHDRAW_PUBLIC_INPUTS);
    pi.push(merkle_root);
    pi.extend_from_slice(nullifiers);
    pi.extend_from_slice(output_commitments);
    pi.push(pallas::Base::from(exit_value));
    pi.push(pallas::Base::from(fee));
    pi
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use lumora_primitives::poseidon;

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

    fn native_nullifier(sk: pallas::Base, commitment: pallas::Base) -> pallas::Base {
        poseidon::hash_two(sk, commitment)
    }

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

    fn zero_hashes() -> [pallas::Base; DEPTH + 1] {
        let mut z = [pallas::Base::zero(); DEPTH + 1];
        for i in 1..=DEPTH {
            z[i] = poseidon::hash_two(z[i - 1], z[i - 1]);
        }
        z
    }

    #[test]
    fn test_valid_withdrawal() {
        let sk = pallas::Base::from(42u64);
        let asset = 0u64;

        // Input 0: value 100
        let r_in0 = pallas::Base::from(111u64);
        let cm_in0 = native_commitment(sk, 100, asset, r_in0);

        // Input 1: value 50
        let r_in1 = pallas::Base::from(222u64);
        let cm_in1 = native_commitment(sk, 50, asset, r_in1);

        let zh = zero_hashes();

        let mut path0 = [pallas::Base::zero(); DEPTH];
        path0[0] = cm_in1;
        path0[1..DEPTH].copy_from_slice(&zh[1..DEPTH]);

        let mut path1 = [pallas::Base::zero(); DEPTH];
        path1[0] = cm_in0;
        path1[1..DEPTH].copy_from_slice(&zh[1..DEPTH]);

        let root = native_merkle_root(cm_in0, &path0, 0);
        assert_eq!(root, native_merkle_root(cm_in1, &path1, 1));

        let nf0 = native_nullifier(sk, cm_in0);
        let nf1 = native_nullifier(sk, cm_in1);

        // Withdraw 70, change 80 (= 100 + 50 - 70)
        let exit_value = 70u64;
        let recipient = pallas::Base::from(99u64);
        let r_out0 = pallas::Base::from(333u64);
        let r_out1 = pallas::Base::from(444u64);
        let cm_out0 = native_commitment(recipient, 80, asset, r_out0);
        let cm_out1 = native_commitment(recipient, 0, asset, r_out1); // dummy change

        let circuit = build_withdraw_circuit(
            &[
                (sk, 100, asset, r_in0, cm_in0, path0, 0),
                (sk, 50, asset, r_in1, cm_in1, path1, 1),
            ],
            &[
                (recipient, 80, asset, r_out0),
                (recipient, 0, asset, r_out1),
            ],
            exit_value,
            0, // fee = 0
        );

        let public_inputs = withdraw_public_inputs(
            root,
            &[nf0, nf1],
            &[cm_out0, cm_out1],
            exit_value,
            0, // fee = 0
        );

        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_withdraw_value_mismatch_fails() {
        let sk = pallas::Base::from(42u64);
        let asset = 0u64;

        let r_in0 = pallas::Base::from(111u64);
        let cm_in0 = native_commitment(sk, 100, asset, r_in0);
        let r_in1 = pallas::Base::from(222u64);
        let cm_in1 = native_commitment(sk, 50, asset, r_in1);

        let zh = zero_hashes();

        let mut path0 = [pallas::Base::zero(); DEPTH];
        path0[0] = cm_in1;
        path0[1..DEPTH].copy_from_slice(&zh[1..DEPTH]);

        let mut path1 = [pallas::Base::zero(); DEPTH];
        path1[0] = cm_in0;
        path1[1..DEPTH].copy_from_slice(&zh[1..DEPTH]);

        let root = native_merkle_root(cm_in0, &path0, 0);
        let nf0 = native_nullifier(sk, cm_in0);
        let nf1 = native_nullifier(sk, cm_in1);

        let recipient = pallas::Base::from(99u64);
        let r_out0 = pallas::Base::from(333u64);
        let r_out1 = pallas::Base::from(444u64);
        let cm_out0 = native_commitment(recipient, 80, asset, r_out0);
        let cm_out1 = native_commitment(recipient, 0, asset, r_out1);

        // Claim exit_value = 90 but change = 80 → 80 + 90 = 170 ≠ 150
        let wrong_exit = 90u64;

        let circuit = build_withdraw_circuit(
            &[
                (sk, 100, asset, r_in0, cm_in0, path0, 0),
                (sk, 50, asset, r_in1, cm_in1, path1, 1),
            ],
            &[
                (recipient, 80, asset, r_out0),
                (recipient, 0, asset, r_out1),
            ],
            wrong_exit,
            0, // fee = 0
        );

        let public_inputs = withdraw_public_inputs(
            root,
            &[nf0, nf1],
            &[cm_out0, cm_out1],
            wrong_exit,
            0, // fee = 0
        );

        let k = 13;
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err(), "Mismatched exit_value should fail");
    }
}
