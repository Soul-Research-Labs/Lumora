use criterion::{criterion_group, criterion_main, Criterion};
use ff::Field;
use group::Group;
use lumora_note::encryption::{decrypt_note, encrypt_note};
use pasta_curves::pallas;
use rand_core::OsRng;

fn bench_encrypt_note(c: &mut Criterion) {
    let recipient_sk = pallas::Scalar::random(OsRng);
    let recipient_pk = pallas::Point::generator() * recipient_sk;
    let randomness = pallas::Scalar::random(OsRng);

    c.bench_function("encrypt_note", |b| {
        b.iter(|| {
            encrypt_note(recipient_pk, 1000, 0, randomness, OsRng)
        });
    });
}

fn bench_decrypt_note(c: &mut Criterion) {
    let recipient_sk = pallas::Scalar::random(OsRng);
    let recipient_pk = pallas::Point::generator() * recipient_sk;
    let randomness = pallas::Scalar::random(OsRng);

    let (eph_pk_bytes, ciphertext) = encrypt_note(recipient_pk, 1000, 0, randomness, OsRng);

    c.bench_function("decrypt_note", |b| {
        b.iter(|| {
            let result = decrypt_note(recipient_sk, &eph_pk_bytes, &ciphertext);
            assert!(result.is_some());
        });
    });
}

fn bench_encrypt_decrypt_roundtrip(c: &mut Criterion) {
    let recipient_sk = pallas::Scalar::random(OsRng);
    let recipient_pk = pallas::Point::generator() * recipient_sk;

    c.bench_function("encrypt_decrypt_roundtrip", |b| {
        b.iter(|| {
            let randomness = pallas::Scalar::random(OsRng);
            let (eph_pk_bytes, ciphertext) = encrypt_note(recipient_pk, 500, 1, randomness, OsRng);
            let result = decrypt_note(recipient_sk, &eph_pk_bytes, &ciphertext);
            assert!(result.is_some());
        });
    });
}

criterion_group!(benches, bench_encrypt_note, bench_decrypt_note, bench_encrypt_decrypt_roundtrip);
criterion_main!(benches);
