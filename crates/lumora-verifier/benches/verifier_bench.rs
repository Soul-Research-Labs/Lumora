use criterion::{criterion_group, criterion_main, Criterion};
use lumora_note::keys::scalar_to_base;
use lumora_note::{Note, SpendingKey};
use lumora_prover::{
    circuit_commitment, prove_transfer, setup, InputNote, OutputNote,
};
use lumora_tree::IncrementalMerkleTree;
use lumora_verifier::{verify_transfer_proof, batch_verify_transfers, TransferBatchItem};
use pasta_curves::pallas;

/// Build a valid transfer proof for benchmarking verification.
fn build_proof() -> (lumora_prover::VerifierParams, lumora_prover::TransferProof) {
    let (prover, verifier) = setup().expect("transfer setup");

    let sk = SpendingKey::from_scalar(pallas::Scalar::from(42u64));
    let sk_base = scalar_to_base(sk.inner());

    let r1 = scalar_to_base(pallas::Scalar::from(111u64));
    let r2 = scalar_to_base(pallas::Scalar::from(222u64));
    let r_out1 = pallas::Base::from(333u64);
    let r_out2 = pallas::Base::from(444u64);

    let cm1 = circuit_commitment(sk_base, 60, 0, r1);
    let cm2 = circuit_commitment(sk_base, 40, 0, r2);

    let mut tree = IncrementalMerkleTree::new();
    tree.insert(cm1);
    tree.insert(cm2);

    let inputs = [
        InputNote {
            spending_key: sk.clone(),
            note: Note { owner: sk_base, value: 60, asset: 0, randomness: pallas::Scalar::from(111u64) },
            merkle_index: 0,
        },
        InputNote {
            spending_key: sk.clone(),
            note: Note { owner: sk_base, value: 40, asset: 0, randomness: pallas::Scalar::from(222u64) },
            merkle_index: 1,
        },
    ];

    let recipient = pallas::Base::from(0xBEEFu64);
    let outputs = [
        OutputNote { owner_pubkey_field: recipient, value: 70, asset: 0, randomness: r_out1 },
        OutputNote { owner_pubkey_field: sk_base, value: 30, asset: 0, randomness: r_out2 },
    ];

    let proof = prove_transfer(&prover, &inputs, &outputs, &mut tree, 0)
        .expect("prove should succeed");
    (verifier, proof)
}

fn bench_verify_transfer(c: &mut Criterion) {
    let (verifier, proof) = build_proof();

    c.bench_function("verify_transfer_proof", |b| {
        b.iter(|| {
            let ok = verify_transfer_proof(
                &verifier,
                &proof.proof_bytes,
                proof.merkle_root,
                &proof.nullifiers,
                &proof.output_commitments,
                proof.fee,
            );
            assert!(ok);
        });
    });
}

fn bench_batch_verify_4(c: &mut Criterion) {
    let (verifier, proof) = build_proof();

    let items: Vec<TransferBatchItem> = (0..4)
        .map(|_| TransferBatchItem {
            proof_bytes: proof.proof_bytes.clone(),
            merkle_root: proof.merkle_root,
            nullifiers: proof.nullifiers,
            output_commitments: proof.output_commitments,
            fee: proof.fee,
        })
        .collect();

    c.bench_function("batch_verify_4_transfers", |b| {
        b.iter(|| {
            let ok = batch_verify_transfers(&verifier, &items);
            assert!(ok);
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_transfer, bench_batch_verify_4
}
criterion_main!(benches);
