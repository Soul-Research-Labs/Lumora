//! Poseidon hash chip wrapper for use in LUMORA circuits.
//!
//! Wraps `halo2_gadgets::poseidon` with our PoseidonSpec (width 3, rate 2)
//! so that in-circuit hashing matches the native `lumora_primitives::poseidon::hash_two`.

use halo2_gadgets::poseidon::{
    primitives::ConstantLength, Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};
use pasta_curves::pallas;

use lumora_primitives::poseidon::PoseidonSpec;

/// Configuration for the Poseidon chip in LUMORA circuits.
#[derive(Clone, Debug)]
pub struct PoseidonChipConfig {
    pub pow5_config: Pow5Config<pallas::Base, 3, 2>,
}

impl PoseidonChipConfig {
    /// Configure the Poseidon chip.
    ///
    /// Requires 3 advice columns and 2 fixed columns (for round constants and MDS matrix).
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        state: [Column<Advice>; 3],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; 3],
        rc_b: [Column<Fixed>; 3],
    ) -> Self {
        let pow5_config = Pow5Chip::configure::<PoseidonSpec>(meta, state, partial_sbox, rc_a, rc_b);
        Self { pow5_config }
    }

    /// Hash two assigned cells: `H(left, right)` in-circuit.
    pub fn hash_two(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        left: AssignedCell<pallas::Base, pallas::Base>,
        right: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        let chip = Pow5Chip::construct(self.pow5_config.clone());
        let hasher = PoseidonHash::<_, _, PoseidonSpec, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "poseidon_init"),
        )?;
        let result = hasher.hash(
            layouter.namespace(|| "poseidon_hash"),
            [left, right],
        )?;
        Ok(result)
    }
}
