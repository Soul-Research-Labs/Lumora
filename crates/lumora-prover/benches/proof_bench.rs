use criterion::{criterion_group, criterion_main, Criterion};
use lumora_note::keys::scalar_to_base;
use lumora_note::{Note, SpendingKey};
use lumora_prover::{
    circuit_commitment, prove_transfer, setup, InputNote, OutputNote,
};
use lumora_tree::IncrementalMerkleTree;
use pasta_curves::pallas;
use rand_core::OsRng;

fn bench_setup(c: &mut Criterion) {
    c.bench_function("setup_transfer_keys", |b| {
        b.iter(|| {
            let _ = setup().expect("setup");
        });
    });
}

fn bench_prove_transfer(c: &mut Criterion) {
    let (prover_params, _verifier_params) = setup().expect("setup");

    let sk = SpendingKey::random(OsRng);
    let sk_base = scalar_to_base(sk.inner());
    let asset = 0u64;

    // Use small scalars so scalar_to_base is the identity (small u64 fits in both fields).
    let r_scalar_0 = pallas::Scalar::from(111u64);
    let r_scalar_1 = pallas::Scalar::from(222u64);
    let r0 = scalar_to_base(r_scalar_0);
    let r1 = scalar_to_base(r_scalar_1);

    let cm0 = circuit_commitment(sk_base, 70, asset, r0);
    let cm1 = circuit_commitment(sk_base, 30, asset, r1);

    let mut tree = IncrementalMerkleTree::new();
    let idx0 = tree.insert(cm0);
    let idx1 = tree.insert(cm1);

    let inputs = [
        InputNote {
            spending_key: sk.clone(),
            note: Note { owner: sk.public_key_field(), value: 70, asset, randomness: r_scalar_0 },
            merkle_index: idx0,
        },
        InputNote {
            spending_key: sk.clone(),
            note: Note { owner: sk.public_key_field(), value: 30, asset, randomness: r_scalar_1 },
            merkle_index: idx1,
        },
    ];

    let recipient = pallas::Base::from(99u64);
    let outputs = [
        OutputNote { owner_pubkey_field: recipient, value: 60, asset, randomness: pallas::Base::from(333u64) },
        OutputNote { owner_pubkey_field: recipient, value: 40, asset, randomness: pallas::Base::from(444u64) },
    ];

    c.bench_function("prove_transfer", |b| {
        b.iter(|| {
            let _ = prove_transfer(&prover_params, &inputs, &outputs, &mut tree, 0).unwrap();
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_setup, bench_prove_transfer
}
criterion_main!(benches);
