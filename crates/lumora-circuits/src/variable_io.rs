//! #55 — Variable I/O circuit scaffolding.
//!
//! The current transfer and withdraw circuits have fixed 2-in-2-out topology.
//! This module provides the structural groundwork for circuits where the
//! number of inputs and outputs is variable (e.g., 4-in-4-out, 1-in-8-out).
//!
//! The approach pads unused slots with zero-valued dummy notes whose
//! commitments are deterministic, allowing a single circuit layout to handle
//! variable fan-in/fan-out while keeping the Halo2 region structure constant.

use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

/// Upper bound on the number of inputs/outputs in a variable circuit.
pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 8;

/// Describes the actual I/O count for a specific transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoShape {
    pub num_inputs: usize,
    pub num_outputs: usize,
}

impl IoShape {
    pub fn new(num_inputs: usize, num_outputs: usize) -> Result<Self, IoShapeError> {
        if num_inputs == 0 || num_inputs > MAX_INPUTS {
            return Err(IoShapeError::InputCount(num_inputs));
        }
        if num_outputs == 0 || num_outputs > MAX_OUTPUTS {
            return Err(IoShapeError::OutputCount(num_outputs));
        }
        Ok(Self {
            num_inputs,
            num_outputs,
        })
    }

    /// Total public-input count for this shape:
    /// 1 (root) + num_inputs (nullifiers) + num_outputs (commitments) + 1 (fee)
    pub fn public_input_count(&self) -> usize {
        1 + self.num_inputs + self.num_outputs + 1
    }

    /// Number of dummy (padded) inputs required.
    pub fn padding_inputs(&self) -> usize {
        MAX_INPUTS - self.num_inputs
    }

    /// Number of dummy (padded) outputs required.
    pub fn padding_outputs(&self) -> usize {
        MAX_OUTPUTS - self.num_outputs
    }
}

/// Errors from invalid I/O shape specification.
#[derive(Debug)]
pub enum IoShapeError {
    InputCount(usize),
    OutputCount(usize),
}

impl std::fmt::Display for IoShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputCount(n) => write!(f, "invalid input count {n} (max {MAX_INPUTS})"),
            Self::OutputCount(n) => write!(f, "invalid output count {n} (max {MAX_OUTPUTS})"),
        }
    }
}

impl std::error::Error for IoShapeError {}

/// A dummy note used to pad unused slots to zero value.
///
/// The commitment of a dummy note is deterministic (Poseidon hash of all-zero
/// fields), so the verifier can compute expected padding commitments.
#[derive(Clone, Debug)]
pub struct DummyNote {
    pub owner: pallas::Base,
    pub value: u64,
    pub asset: pallas::Base,
    pub randomness: pallas::Base,
}

impl Default for DummyNote {
    fn default() -> Self {
        Self {
            owner: pallas::Base::zero(),
            value: 0,
            asset: pallas::Base::zero(),
            randomness: pallas::Base::zero(),
        }
    }
}

/// Witness layout for a variable-IO transfer.
#[derive(Clone, Debug)]
pub struct VariableTransferWitness {
    pub shape: IoShape,
    /// Actual input values (length == shape.num_inputs).
    pub input_values: Vec<u64>,
    /// Actual output values (length == shape.num_outputs).
    pub output_values: Vec<u64>,
    pub fee: u64,
}

impl VariableTransferWitness {
    /// Verify that value conservation holds: sum(inputs) == sum(outputs) + fee.
    pub fn check_conservation(&self) -> bool {
        let in_sum: u64 = self.input_values.iter().sum();
        let out_sum: u64 = self.output_values.iter().sum();
        in_sum == out_sum.saturating_add(self.fee)
    }

    /// Return the padded input values (with zeros for dummy slots).
    pub fn padded_inputs(&self) -> Vec<u64> {
        let mut v = self.input_values.clone();
        v.resize(MAX_INPUTS, 0);
        v
    }

    /// Return the padded output values (with zeros for dummy slots).
    pub fn padded_outputs(&self) -> Vec<u64> {
        let mut v = self.output_values.clone();
        v.resize(MAX_OUTPUTS, 0);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_validation() {
        assert!(IoShape::new(2, 2).is_ok());
        assert!(IoShape::new(8, 8).is_ok());
        assert!(IoShape::new(0, 2).is_err());
        assert!(IoShape::new(2, 9).is_err());
    }

    #[test]
    fn public_input_count() {
        let shape = IoShape::new(2, 2).unwrap();
        // root + 2 nullifiers + 2 commitments + fee = 6
        assert_eq!(shape.public_input_count(), 6);

        let shape = IoShape::new(4, 4).unwrap();
        assert_eq!(shape.public_input_count(), 10);
    }

    #[test]
    fn padding() {
        let shape = IoShape::new(3, 5).unwrap();
        assert_eq!(shape.padding_inputs(), 5);
        assert_eq!(shape.padding_outputs(), 3);
    }

    #[test]
    fn conservation_check() {
        let w = VariableTransferWitness {
            shape: IoShape::new(2, 2).unwrap(),
            input_values: vec![100, 50],
            output_values: vec![90, 50],
            fee: 10,
        };
        assert!(w.check_conservation());

        let bad = VariableTransferWitness {
            shape: IoShape::new(1, 1).unwrap(),
            input_values: vec![100],
            output_values: vec![100],
            fee: 1,
        };
        assert!(!bad.check_conservation());
    }

    #[test]
    fn padded_vectors() {
        let w = VariableTransferWitness {
            shape: IoShape::new(2, 3).unwrap(),
            input_values: vec![10, 20],
            output_values: vec![5, 10, 15],
            fee: 0,
        };
        assert_eq!(w.padded_inputs().len(), MAX_INPUTS);
        assert_eq!(w.padded_outputs().len(), MAX_OUTPUTS);
        assert_eq!(w.padded_inputs()[2], 0);
    }
}
