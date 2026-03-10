use criterion::{criterion_group, criterion_main, Criterion};
use lumora_contracts::{execute_deposit, DepositRequest, PrivacyPoolState};
use pasta_curves::pallas;

fn bench_deposit(c: &mut Criterion) {
    let mut state = PrivacyPoolState::new();
    let commitment = pallas::Base::from(12345u64);

    c.bench_function("execute_deposit", |bench| {
        bench.iter(|| {
            let req = DepositRequest {
                commitment,
                amount: 1000,
            };
            let _ = execute_deposit(&mut state, &req);
        });
    });
}

fn bench_deposit_100(c: &mut Criterion) {
    c.bench_function("deposit_100_sequential", |bench| {
        bench.iter(|| {
            let mut state = PrivacyPoolState::new();
            for i in 0..100u64 {
                let req = DepositRequest {
                    commitment: pallas::Base::from(i),
                    amount: 1000,
                };
                let _ = execute_deposit(&mut state, &req);
            }
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_deposit, bench_deposit_100
}
criterion_main!(benches);
