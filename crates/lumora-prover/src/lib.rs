//! LUMORA Prover — proof generation engine.
//!
//! Provides a high-level API to:
//! 1. Generate proving/verifying keys from the circuit.
//! 2. Create a proof given input/output notes and Merkle tree state.
//! 3. Serialize proofs for on-chain verification.

pub mod async_prove;
pub mod pipeline;

use std::io;
use std::path::Path;
use std::sync::Arc;

use halo2_proofs::{
    plonk::{
        self, create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use rand_core::OsRng;

use lumora_circuits::CircuitVersion;
use lumora_circuits::transfer::{
    build_transfer_circuit, transfer_public_inputs, InputNoteWitness, OutputNoteWitness,
    TransferCircuit, NUM_INPUTS, NUM_OUTPUTS,
};
use lumora_circuits::withdraw::{
    build_withdraw_circuit, withdraw_public_inputs, WithdrawCircuit,
};
use lumora_note::{Note, SpendingKey};
use lumora_note::keys::scalar_to_base;
use lumora_primitives::poseidon;
use lumora_tree::{IncrementalMerkleTree, DEPTH};

/// The circuit size parameter. k=13 → 2^13 = 8192 rows.
/// Sufficient for a 2-in-2-out transfer with depth-32 Merkle path.
pub const K: u32 = 13;

/// A generated transfer proof along with its public inputs.
#[derive(Clone, Debug)]
pub struct TransferProof {
    pub proof_bytes: Vec<u8>,
    pub merkle_root: pallas::Base,
    pub nullifiers: [pallas::Base; NUM_INPUTS],
    pub output_commitments: [pallas::Base; NUM_OUTPUTS],
    /// Transaction fee (enforced by the circuit).
    pub fee: u64,
    /// The circuit version that generated this proof.
    pub circuit_version: CircuitVersion,
}

impl TransferProof {
    /// Assemble the public inputs vector (for verification).
    pub fn public_inputs(&self) -> Vec<pallas::Base> {
        transfer_public_inputs(
            self.merkle_root,
            &self.nullifiers,
            &self.output_commitments,
            self.fee,
        )
    }

    /// Size of the proof in bytes.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len()
    }
}

/// Parameters bundle for proving.
pub struct ProverParams {
    pub params: Params<vesta::Affine>,
    pub pk: ProvingKey<vesta::Affine>,
}

/// Parameters bundle for verification (extracted from prover params).
pub struct VerifierParams {
    pub params: Params<vesta::Affine>,
    pub vk: VerifyingKey<vesta::Affine>,
}

/// Generate fresh SRS parameters (expensive — involves multi-scalar multiplication).
pub fn generate_params() -> Params<vesta::Affine> {
    Params::new(K)
}

/// Generate proving and verifying keys for the transfer circuit.
///
/// This is expensive (~seconds) and should be done once, then reused.
pub fn setup() -> Result<(ProverParams, VerifierParams), plonk::Error> {
    let params = generate_params();
    setup_from_params(params)
}

/// Save SRS parameters to a file so they can be reused across runs.
pub fn save_params<P: AsRef<Path>>(params: &Params<vesta::Affine>, path: P) -> io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    params.write(&mut file)
}

/// Load SRS parameters from a file.
pub fn load_params<P: AsRef<Path>>(path: P) -> io::Result<Params<vesta::Affine>> {
    let mut file = std::fs::File::open(path)?;
    Params::read(&mut file)
}

/// Generate proving and verifying keys for the transfer circuit from existing SRS params.
///
/// This is faster than `setup()` since it skips SRS generation.
pub fn setup_from_params(params: Params<vesta::Affine>) -> Result<(ProverParams, VerifierParams), plonk::Error> {
    let empty_circuit = empty_transfer_circuit();
    let vk = keygen_vk(&params, &empty_circuit)?;
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)?;

    Ok((
        ProverParams {
            params: params.clone(),
            pk,
        },
        VerifierParams { params, vk },
    ))
}

/// Generate withdrawal keys from existing SRS params.
pub fn setup_withdraw_from_params(
    params: Params<vesta::Affine>,
) -> Result<(WithdrawProverParams, WithdrawVerifierParams), plonk::Error> {
    let empty_circuit = empty_withdraw_circuit();
    let vk = keygen_vk(&params, &empty_circuit)?;
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)?;

    Ok((
        WithdrawProverParams {
            params: params.clone(),
            pk,
        },
        WithdrawVerifierParams { params, vk },
    ))
}

fn empty_transfer_circuit() -> TransferCircuit {
    TransferCircuit {
        inputs: std::array::from_fn(|_| InputNoteWitness {
            spending_key: halo2_proofs::circuit::Value::unknown(),
            value: halo2_proofs::circuit::Value::unknown(),
            asset: halo2_proofs::circuit::Value::unknown(),
            randomness: halo2_proofs::circuit::Value::unknown(),
            commitment: halo2_proofs::circuit::Value::unknown(),
            merkle_path: [halo2_proofs::circuit::Value::unknown(); DEPTH],
            merkle_index: halo2_proofs::circuit::Value::unknown(),
            domain_chain_id: None,
            domain_app_id: None,
        }),
        outputs: std::array::from_fn(|_| OutputNoteWitness {
            owner: halo2_proofs::circuit::Value::unknown(),
            value: halo2_proofs::circuit::Value::unknown(),
            asset: halo2_proofs::circuit::Value::unknown(),
            randomness: halo2_proofs::circuit::Value::unknown(),
        }),
        fee: halo2_proofs::circuit::Value::unknown(),
    }
}

fn empty_withdraw_circuit() -> WithdrawCircuit {
    WithdrawCircuit {
        inputs: std::array::from_fn(|_| InputNoteWitness {
            spending_key: halo2_proofs::circuit::Value::unknown(),
            value: halo2_proofs::circuit::Value::unknown(),
            asset: halo2_proofs::circuit::Value::unknown(),
            randomness: halo2_proofs::circuit::Value::unknown(),
            commitment: halo2_proofs::circuit::Value::unknown(),
            merkle_path: [halo2_proofs::circuit::Value::unknown(); DEPTH],
            merkle_index: halo2_proofs::circuit::Value::unknown(),
            domain_chain_id: None,
            domain_app_id: None,
        }),
        outputs: std::array::from_fn(|_| OutputNoteWitness {
            owner: halo2_proofs::circuit::Value::unknown(),
            value: halo2_proofs::circuit::Value::unknown(),
            asset: halo2_proofs::circuit::Value::unknown(),
            randomness: halo2_proofs::circuit::Value::unknown(),
        }),
        exit_value: halo2_proofs::circuit::Value::unknown(),
        fee: halo2_proofs::circuit::Value::unknown(),
    }
}

/// Data needed to spend one input note.
pub struct InputNote {
    pub spending_key: SpendingKey,
    pub note: Note,
    pub merkle_index: u64,
}

/// Data for one output note.
pub struct OutputNote {
    pub owner_pubkey_field: pallas::Base,
    pub value: u64,
    pub asset: u64,
    pub randomness: pallas::Base,
}

/// Compute the in-circuit commitment (Poseidon-based, matching the circuit).
///
/// `commitment = hash(hash(hash(owner, value), asset), randomness)`
pub fn circuit_commitment(
    owner: pallas::Base,
    value: u64,
    asset: u64,
    randomness: pallas::Base,
) -> pallas::Base {
    let inner = poseidon::hash_two(owner, pallas::Base::from(value));
    let content = poseidon::hash_two(inner, pallas::Base::from(asset));
    poseidon::hash_two(content, randomness)
}

/// Generate a transfer proof.
///
/// # Arguments
/// - `prover_params`: proving key and SRS params (from `setup()`).
/// - `inputs`: the notes being spent + their Merkle indices.
/// - `outputs`: the new notes being created.
/// - `tree`: the current Merkle tree state.
/// - `fee`: transaction fee (enforced by the circuit).
pub fn prove_transfer(
    prover_params: &ProverParams,
    inputs: &[InputNote; NUM_INPUTS],
    outputs: &[OutputNote; NUM_OUTPUTS],
    tree: &mut IncrementalMerkleTree,
    fee: u64,
) -> Result<TransferProof, plonk::Error> {
    let merkle_root = tree.root();

    // Build circuit witness for each input.
    let mut input_data = Vec::new();
    let mut nullifiers = [pallas::Base::zero(); NUM_INPUTS];

    for (i, inp) in inputs.iter().enumerate() {
        let sk_base = scalar_to_base(inp.spending_key.inner());
        let randomness_base = scalar_to_base(inp.note.randomness);

        // Compute the in-circuit commitment.
        let commitment = circuit_commitment(
            sk_base, // In-circuit we use sk directly as the "owner" field
            inp.note.value,
            inp.note.asset,
            randomness_base,
        );

        // Get Merkle path.
        let path = tree
            .witness(inp.merkle_index)
            .ok_or(plonk::Error::Synthesis)?; // Bug #16: note not in tree → synthesis error

        if path.siblings.len() != DEPTH {
            return Err(plonk::Error::Synthesis); // Bug #17: path length mismatch
        }
        let mut siblings = [pallas::Base::zero(); DEPTH];
        siblings.copy_from_slice(&path.siblings);

        // Compute nullifier.
        let nf = poseidon::hash_two(sk_base, commitment);
        nullifiers[i] = nf;

        input_data.push((
            sk_base,
            inp.note.value,
            inp.note.asset,
            randomness_base,
            commitment,
            siblings,
            inp.merkle_index,
        ));
    }

    // Build circuit witness for each output.
    let mut output_data = Vec::new();
    let mut output_commitments = [pallas::Base::zero(); NUM_OUTPUTS];

    for (i, out) in outputs.iter().enumerate() {
        let commitment = circuit_commitment(
            out.owner_pubkey_field,
            out.value,
            out.asset,
            out.randomness,
        );
        output_commitments[i] = commitment;
        output_data.push((out.owner_pubkey_field, out.value, out.asset, out.randomness));
    }

    // Build the circuit.
    let circuit = build_transfer_circuit(
        &[input_data[0], input_data[1]],
        &[output_data[0], output_data[1]],
        fee,
    );

    // Generate the proof.
    let public_inputs = transfer_public_inputs(merkle_root, &nullifiers, &output_commitments, fee);

    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    create_proof(
        &prover_params.params,
        &prover_params.pk,
        &[circuit],
        &[&[&public_inputs]],
        &mut OsRng,
        &mut transcript,
    )?;

    let proof_bytes = transcript.finalize();

    Ok(TransferProof {
        proof_bytes,
        merkle_root,
        nullifiers,
        output_commitments,
        fee,
        circuit_version: CircuitVersion::CURRENT,
    })
}

// ============================================================================
// Withdrawal proof support
// ============================================================================

/// A generated withdrawal proof along with its public inputs.
#[derive(Clone, Debug)]
pub struct WithdrawProof {
    pub proof_bytes: Vec<u8>,
    pub merkle_root: pallas::Base,
    pub nullifiers: [pallas::Base; NUM_INPUTS],
    pub output_commitments: [pallas::Base; NUM_OUTPUTS],
    pub exit_value: u64,
    /// Transaction fee (enforced by the circuit).
    pub fee: u64,
    /// The circuit version that generated this proof.
    pub circuit_version: CircuitVersion,
}

impl WithdrawProof {
    pub fn public_inputs(&self) -> Vec<pallas::Base> {
        withdraw_public_inputs(
            self.merkle_root,
            &self.nullifiers,
            &self.output_commitments,
            self.exit_value,
            self.fee,
        )
    }

    /// Size of the proof in bytes.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes.len()
    }
}

/// Prover params for the withdrawal circuit.
pub struct WithdrawProverParams {
    pub params: Params<vesta::Affine>,
    pub pk: ProvingKey<vesta::Affine>,
}

/// Verifier params for the withdrawal circuit.
pub struct WithdrawVerifierParams {
    pub params: Params<vesta::Affine>,
    pub vk: VerifyingKey<vesta::Affine>,
}

/// Generate proving and verifying keys for the withdrawal circuit.
pub fn setup_withdraw() -> Result<(WithdrawProverParams, WithdrawVerifierParams), plonk::Error> {
    let params = generate_params();
    setup_withdraw_from_params(params)
}

/// Generate a withdrawal proof.
pub fn prove_withdraw(
    prover_params: &WithdrawProverParams,
    inputs: &[InputNote; NUM_INPUTS],
    outputs: &[OutputNote; NUM_OUTPUTS],
    tree: &mut IncrementalMerkleTree,
    exit_value: u64,
    fee: u64,
) -> Result<WithdrawProof, plonk::Error> {
    let merkle_root = tree.root();

    let mut input_data = Vec::new();
    let mut nullifiers = [pallas::Base::zero(); NUM_INPUTS];

    for (i, inp) in inputs.iter().enumerate() {
        let sk_base = scalar_to_base(inp.spending_key.inner());
        let randomness_base = scalar_to_base(inp.note.randomness);

        let commitment = circuit_commitment(
            sk_base,
            inp.note.value,
            inp.note.asset,
            randomness_base,
        );

        let path = tree
            .witness(inp.merkle_index)
            .ok_or(plonk::Error::Synthesis)?; // Bug #16: note not in tree → synthesis error

        if path.siblings.len() != DEPTH {
            return Err(plonk::Error::Synthesis); // Bug #17: path length mismatch
        }
        let mut siblings = [pallas::Base::zero(); DEPTH];
        siblings.copy_from_slice(&path.siblings);

        let nf = poseidon::hash_two(sk_base, commitment);
        nullifiers[i] = nf;

        input_data.push((
            sk_base,
            inp.note.value,
            inp.note.asset,
            randomness_base,
            commitment,
            siblings,
            inp.merkle_index,
        ));
    }

    let mut output_data = Vec::new();
    let mut output_commitments = [pallas::Base::zero(); NUM_OUTPUTS];

    for (i, out) in outputs.iter().enumerate() {
        let commitment = circuit_commitment(
            out.owner_pubkey_field,
            out.value,
            out.asset,
            out.randomness,
        );
        output_commitments[i] = commitment;
        output_data.push((out.owner_pubkey_field, out.value, out.asset, out.randomness));
    }

    let circuit = build_withdraw_circuit(
        &[input_data[0], input_data[1]],
        &[output_data[0], output_data[1]],
        exit_value,
        fee,
    );

    let public_inputs = withdraw_public_inputs(
        merkle_root,
        &nullifiers,
        &output_commitments,
        exit_value,
        fee,
    );

    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    create_proof(
        &prover_params.params,
        &prover_params.pk,
        &[circuit],
        &[&[&public_inputs]],
        &mut OsRng,
        &mut transcript,
    )?;

    let proof_bytes = transcript.finalize();

    Ok(WithdrawProof {
        proof_bytes,
        merkle_root,
        nullifiers,
        output_commitments,
        exit_value,
        fee,
        circuit_version: CircuitVersion::CURRENT,
    })
}

// ============================================================================
// Thread-safe prover handles
// ============================================================================

/// Thread-safe handle to transfer prover params.
///
/// Wraps `ProverParams` in an `Arc` so multiple threads can generate proofs
/// concurrently using the same proving key and SRS.
///
/// ```rust,ignore
/// let handle = SharedProverHandle::new(prover_params);
/// std::thread::scope(|s| {
///     s.spawn(|| prove_transfer(&handle, &inputs1, &outputs1, &mut tree1));
///     s.spawn(|| prove_transfer(&handle, &inputs2, &outputs2, &mut tree2));
/// });
/// ```
#[derive(Clone)]
pub struct SharedProverHandle {
    inner: Arc<ProverParams>,
}

impl SharedProverHandle {
    pub fn new(params: ProverParams) -> Self {
        Self { inner: Arc::new(params) }
    }
}

impl std::ops::Deref for SharedProverHandle {
    type Target = ProverParams;
    fn deref(&self) -> &ProverParams {
        &self.inner
    }
}

/// Thread-safe handle to withdrawal prover params.
#[derive(Clone)]
pub struct SharedWithdrawProverHandle {
    inner: Arc<WithdrawProverParams>,
}

impl SharedWithdrawProverHandle {
    pub fn new(params: WithdrawProverParams) -> Self {
        Self { inner: Arc::new(params) }
    }
}

impl std::ops::Deref for SharedWithdrawProverHandle {
    type Target = WithdrawProverParams;
    fn deref(&self) -> &WithdrawProverParams {
        &self.inner
    }
}

// ============================================================================
// Parallel proof generation
// ============================================================================

/// A bundle of transfer proving inputs (inputs, outputs, and a local tree clone).
pub struct TransferJob {
    pub inputs: [InputNote; NUM_INPUTS],
    pub outputs: [OutputNote; NUM_OUTPUTS],
    pub tree: IncrementalMerkleTree,
    pub fee: u64,
}

/// Generate multiple transfer proofs in parallel using rayon.
///
/// Each job gets its own tree clone (because `prove_transfer` needs `&mut tree`
/// to compute Merkle paths). Returns results in the same order as the input jobs.
pub fn prove_transfers_parallel(
    handle: &SharedProverHandle,
    jobs: Vec<TransferJob>,
) -> Vec<Result<TransferProof, plonk::Error>> {
    use rayon::prelude::*;

    jobs.into_par_iter()
        .map(|mut job| prove_transfer(handle, &job.inputs, &job.outputs, &mut job.tree, job.fee))
        .collect()
}

/// A bundle of withdraw proving inputs.
pub struct WithdrawJob {
    pub inputs: [InputNote; NUM_INPUTS],
    pub outputs: [OutputNote; NUM_OUTPUTS],
    pub tree: IncrementalMerkleTree,
    pub exit_value: u64,
    pub fee: u64,
}

/// Generate multiple withdrawal proofs in parallel using rayon.
pub fn prove_withdrawals_parallel(
    handle: &SharedWithdrawProverHandle,
    jobs: Vec<WithdrawJob>,
) -> Vec<Result<WithdrawProof, plonk::Error>> {
    use rayon::prelude::*;

    jobs.into_par_iter()
        .map(|mut job| {
            prove_withdraw(handle, &job.inputs, &job.outputs, &mut job.tree, job.exit_value, job.fee)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_commitment_deterministic() {
        let owner = pallas::Base::from(42u64);
        let c1 = circuit_commitment(owner, 100, 0, pallas::Base::from(1u64));
        let c2 = circuit_commitment(owner, 100, 0, pallas::Base::from(1u64));
        assert_eq!(c1, c2);
    }

    #[test]
    fn circuit_commitment_differs_for_different_inputs() {
        let owner = pallas::Base::from(42u64);
        let c1 = circuit_commitment(owner, 100, 0, pallas::Base::from(1u64));
        let c2 = circuit_commitment(owner, 200, 0, pallas::Base::from(1u64));
        assert_ne!(c1, c2);
    }

    #[test]
    fn srs_save_load_roundtrip() {
        let original_params = Params::new(K);

        let dir = std::env::temp_dir().join("lumora_test_srs");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("params.bin");

        save_params(&original_params, &path).expect("save_params should succeed");
        let loaded_params = load_params(&path).expect("load_params should succeed");

        // The loaded params should produce a working transfer setup.
        let (prover, _verifier) = setup_from_params(loaded_params).expect("setup_from_params");

        // Build a trivial proof to confirm the loaded keys work.
        let sk = lumora_note::SpendingKey::from_scalar(pallas::Scalar::from(1u64));
        let sk_base = scalar_to_base(sk.inner());
        let r1 = pallas::Base::from(11u64);
        let r2 = pallas::Base::from(22u64);

        let cm1 = circuit_commitment(sk_base, 50, 0, r1);
        let cm2 = circuit_commitment(sk_base, 50, 0, r2);

        let mut tree = lumora_tree::IncrementalMerkleTree::new();
        tree.insert(cm1);
        tree.insert(cm2);

        let inputs = [
            InputNote {
                spending_key: sk.clone(),
                note: lumora_note::Note { owner: sk_base, value: 50, asset: 0, randomness: pallas::Scalar::from(11u64) },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk.clone(),
                note: lumora_note::Note { owner: sk_base, value: 50, asset: 0, randomness: pallas::Scalar::from(22u64) },
                merkle_index: 1,
            },
        ];

        let outputs = [
            OutputNote { owner_pubkey_field: sk_base, value: 60, asset: 0, randomness: pallas::Base::from(33u64) },
            OutputNote { owner_pubkey_field: sk_base, value: 40, asset: 0, randomness: pallas::Base::from(44u64) },
        ];

        let proof = prove_transfer(&prover, &inputs, &outputs, &mut tree, 0);
        assert!(proof.is_ok(), "prove with loaded params must succeed");

        // Clean up.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn circuit_commitment_zero_values() {
        let zero = pallas::Base::zero();
        let c = circuit_commitment(zero, 0, 0, zero);
        // Must produce a deterministic non-zero hash (Poseidon never maps all-zero to zero).
        let c2 = circuit_commitment(zero, 0, 0, zero);
        assert_eq!(c, c2);
    }

    #[test]
    fn circuit_commitment_differs_by_owner() {
        let r = pallas::Base::from(1u64);
        let c1 = circuit_commitment(pallas::Base::from(1u64), 100, 0, r);
        let c2 = circuit_commitment(pallas::Base::from(2u64), 100, 0, r);
        assert_ne!(c1, c2, "different owners must produce different commitments");
    }

    #[test]
    fn circuit_commitment_differs_by_asset() {
        let owner = pallas::Base::from(42u64);
        let r = pallas::Base::from(1u64);
        let c1 = circuit_commitment(owner, 100, 0, r);
        let c2 = circuit_commitment(owner, 100, 1, r);
        assert_ne!(c1, c2, "different assets must produce different commitments");
    }

    #[test]
    fn circuit_commitment_differs_by_randomness() {
        let owner = pallas::Base::from(42u64);
        let c1 = circuit_commitment(owner, 100, 0, pallas::Base::from(1u64));
        let c2 = circuit_commitment(owner, 100, 0, pallas::Base::from(2u64));
        assert_ne!(c1, c2, "different randomness must produce different commitments");
    }

    #[test]
    fn circuit_commitment_max_value() {
        let owner = pallas::Base::from(1u64);
        let r = pallas::Base::from(1u64);
        // u64::MAX should not panic.
        let c = circuit_commitment(owner, u64::MAX, u64::MAX, r);
        let c2 = circuit_commitment(owner, u64::MAX, u64::MAX, r);
        assert_eq!(c, c2);
    }

    #[test]
    fn transfer_proof_public_inputs_length() {
        // Public inputs: 1 root + NUM_INPUTS nullifiers + NUM_OUTPUTS commitments + 1 fee
        let expected_len = 1 + NUM_INPUTS + NUM_OUTPUTS + 1;
        let root = pallas::Base::from(1u64);
        let nfs = [pallas::Base::from(2u64); NUM_INPUTS];
        let cms = [pallas::Base::from(3u64); NUM_OUTPUTS];
        let pis = lumora_circuits::transfer::transfer_public_inputs(root, &nfs, &cms, 10);
        assert_eq!(pis.len(), expected_len);
    }

    #[test]
    fn withdraw_proof_public_inputs_length() {
        // Public inputs: 1 root + NUM_INPUTS nullifiers + NUM_OUTPUTS commitments + 1 exit_value + 1 fee
        let expected_len = 1 + NUM_INPUTS + NUM_OUTPUTS + 2;
        let root = pallas::Base::from(1u64);
        let nfs = [pallas::Base::from(2u64); NUM_INPUTS];
        let cms = [pallas::Base::from(3u64); NUM_OUTPUTS];
        let pis = lumora_circuits::withdraw::withdraw_public_inputs(root, &nfs, &cms, 100, 10);
        assert_eq!(pis.len(), expected_len);
    }

    #[test]
    fn transfer_proof_metadata() {
        let (_prover, _, proof) = build_test_proof();
        assert!(proof.proof_size() > 0, "proof should have non-zero size");
        assert_eq!(proof.fee, 0);
        assert_eq!(proof.circuit_version, CircuitVersion::CURRENT);
        // Public inputs should be reconstructable.
        let pis = proof.public_inputs();
        assert_eq!(pis[0], proof.merkle_root, "first PI should be merkle root");
    }

    #[test]
    fn shared_prover_handle_deref() {
        let (prover, _) = setup().expect("setup");
        let handle = SharedProverHandle::new(prover);
        // Can access inner fields via Deref.
        let _ = &handle.pk;
        let _ = &handle.params;
        // Clone should work.
        let _cloned = handle.clone();
    }

    #[test]
    fn shared_withdraw_prover_handle_deref() {
        let (wp, _) = setup_withdraw().expect("withdraw setup");
        let handle = SharedWithdrawProverHandle::new(wp);
        let _ = &handle.pk;
        let _cloned = handle.clone();
    }

    #[test]
    fn generate_params_returns_usable_params() {
        let params = generate_params();
        // Should be able to set up keys from these params.
        let result = setup_from_params(params);
        assert!(result.is_ok());
    }

    /// Helper: build a simple transfer proof for metadata tests.
    fn build_test_proof() -> (ProverParams, VerifierParams, TransferProof) {
        let (prover, verifier) = setup().expect("setup");
        let sk = SpendingKey::from_scalar(pallas::Scalar::from(1u64));
        let sk_base = scalar_to_base(sk.inner());
        let r1 = pallas::Base::from(11u64);
        let r2 = pallas::Base::from(22u64);

        let cm1 = circuit_commitment(sk_base, 50, 0, r1);
        let cm2 = circuit_commitment(sk_base, 50, 0, r2);

        let mut tree = IncrementalMerkleTree::new();
        tree.insert(cm1);
        tree.insert(cm2);

        let inputs = [
            InputNote {
                spending_key: sk.clone(),
                note: Note { owner: sk_base, value: 50, asset: 0, randomness: pallas::Scalar::from(11u64) },
                merkle_index: 0,
            },
            InputNote {
                spending_key: sk.clone(),
                note: Note { owner: sk_base, value: 50, asset: 0, randomness: pallas::Scalar::from(22u64) },
                merkle_index: 1,
            },
        ];

        let outputs = [
            OutputNote { owner_pubkey_field: sk_base, value: 60, asset: 0, randomness: pallas::Base::from(33u64) },
            OutputNote { owner_pubkey_field: sk_base, value: 40, asset: 0, randomness: pallas::Base::from(44u64) },
        ];

        let proof = prove_transfer(&prover, &inputs, &outputs, &mut tree, 0).expect("prove");
        (prover, verifier, proof)
    }
}
