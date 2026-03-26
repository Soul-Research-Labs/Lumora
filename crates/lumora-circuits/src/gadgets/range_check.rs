//! Range check gadget — ensures a value fits in N bits.
//!
//! Used to constrain note values to u64 (64 bits), preventing
//! overflow attacks in the value conservation check.
//!
//! Strategy: successive halving decomposition.
//! Starting from the original value, at each step:
//!   `val_i = 2 * val_{i+1} + bit_i`, where `bit_i ∈ {0, 1}`.
//! After 64 steps, `val_64` must equal 0.
//! This proves the original value < 2^64.

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

/// Configuration for the range check chip.
#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    /// Column holding the running quotient (val >> i).
    pub quotient: Column<Advice>,
    /// Column holding the extracted bit.
    pub bit: Column<Advice>,
    /// Selector that activates the decomposition constraint.
    pub selector: Selector,
}

impl RangeCheckConfig {
    /// Configure the range check chip.
    ///
    /// `quotient` and `bit` are advice columns (may be shared with other gadgets
    /// since each range check runs in its own region).
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        quotient: Column<Advice>,
        bit: Column<Advice>,
    ) -> Self {
        let selector = meta.selector();

        meta.create_gate("range check", |meta| {
            let s = meta.query_selector(selector);
            let q_cur = meta.query_advice(quotient, Rotation::cur());
            let q_next = meta.query_advice(quotient, Rotation::next());
            let b = meta.query_advice(bit, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(pallas::Base::one());
            let two = halo2_proofs::plonk::Expression::Constant(pallas::Base::from(2u64));

            // Constraint 1: b ∈ {0, 1}
            let boolean = b.clone() * (one - b.clone());

            // Constraint 2: q_cur = 2 * q_next + b
            //   i.e., q_next = (q_cur - b) / 2  (successive halving)
            let decomp = q_cur - (two * q_next + b);

            Constraints::with_selector(s, [("boolean", boolean), ("decomp", decomp)])
        });

        Self {
            quotient,
            bit,
            selector,
        }
    }

    /// Constrain `value` to be at most 64 bits.
    ///
    /// Uses 65 rows: row 0 = value, rows 0..63 selected, row 64 = 0.
    pub fn range_check_u64(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        let final_q_cell = layouter.assign_region(
            || "range check u64",
            |mut region| {
                // Decompose value into quotients and bits.
                let quotients: Vec<Value<pallas::Base>> = value
                    .value()
                    .map(|v| {
                        let repr = v.to_repr();
                        let val_u64 = u64::from_le_bytes(
                            repr[0..8].try_into().expect("field repr is 32 bytes"),
                        );
                        // Verify no upper bits: bytes 8..31 must all be zero.
                        assert_eq!(
                            *v,
                            pallas::Base::from(val_u64),
                            "range_check_u64: value has bits above bit 63 (exceeds u64 range)"
                        );
                        let mut qs = Vec::with_capacity(65);
                        let mut q = val_u64;
                        for _ in 0..64 {
                            qs.push(q);
                            q >>= 1;
                        }
                        qs.push(0); // q_64 = 0
                        qs.into_iter()
                            .map(pallas::Base::from)
                            .collect::<Vec<_>>()
                    })
                    .transpose_vec(65);

                let bits: Vec<Value<pallas::Base>> = value
                    .value()
                    .map(|v| {
                        let repr = v.to_repr();
                        let val_u64 = u64::from_le_bytes(
                            repr[0..8].try_into().expect("field repr is 32 bytes"),
                        );
                        (0..64)
                            .map(|i| pallas::Base::from((val_u64 >> i) & 1))
                            .collect::<Vec<_>>()
                    })
                    .transpose_vec(64);

                // Assign row 0: copy-constrain input value.
                value.copy_advice(|| "value", &mut region, self.quotient, 0)?;

                // Rows 0..63: enable selector, assign bit.
                let mut last_q_cell = None;
                for i in 0..64 {
                    self.selector.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("bit_{}", i),
                        self.bit,
                        i,
                        || bits[i],
                    )?;
                    // Assign q_{i+1} in the next row's quotient column.
                    let q_cell = region.assign_advice(
                        || format!("q_{}", i + 1),
                        self.quotient,
                        i + 1,
                        || quotients[i + 1],
                    )?;
                    last_q_cell = Some(q_cell);
                }

                // Row 64: the final quotient must be zero.
                Ok(last_q_cell.unwrap())
            },
        )?;

        // Constrain q_64 == 0 using the constant column.
        layouter.assign_region(
            || "constrain q64 = 0",
            |mut region| {
                let z = region.assign_advice_from_constant(
                    || "zero",
                    self.quotient,
                    0,
                    pallas::Base::zero(),
                )?;
                region.constrain_equal(final_q_cell.cell(), z.cell())
            },
        )?;

        Ok(())
    }
}
