use criterion::{criterion_group, criterion_main, Criterion};
use lumora_primitives::poseidon;
use lumora_tree::IncrementalMerkleTree;
use pasta_curves::pallas;

fn bench_poseidon_hash_two(c: &mut Criterion) {
    let a = pallas::Base::from(42u64);
    let b = pallas::Base::from(99u64);
    c.bench_function("poseidon_hash_two", |bench| {
        bench.iter(|| poseidon::hash_two(a, b));
    });
}

fn bench_tree_insert(c: &mut Criterion) {
    c.bench_function("merkle_insert_first_256", |bench| {
        bench.iter(|| {
            let mut tree = IncrementalMerkleTree::new();
            for i in 0..256u64 {
                tree.insert(pallas::Base::from(i));
            }
        });
    });
}

fn bench_tree_root(c: &mut Criterion) {
    let mut tree = IncrementalMerkleTree::new();
    for i in 0..512u64 {
        tree.insert(pallas::Base::from(i));
    }
    c.bench_function("merkle_root_512_leaves", |bench| {
        bench.iter(|| tree.root());
    });
}

criterion_group!(benches, bench_poseidon_hash_two, bench_tree_insert, bench_tree_root);
criterion_main!(benches);
