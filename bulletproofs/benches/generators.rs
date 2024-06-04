#![allow(deprecated)]

use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_secq256k1::Affine;
use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};

fn pc_gens(c: &mut Criterion) {
    c.bench_function("PedersenGens::new", |b| {
        b.iter(PedersenGens::<Affine>::default)
    });
}

fn bp_gens(c: &mut Criterion) {
    let mut group = c.benchmark_group("BulletproofGens::new");
    for size in (0..10).map(|i| 2 << i) {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| BulletproofGens::<Affine>::new(size, 1))
        });
    }
}

criterion_group!(bp, bp_gens, pc_gens);
criterion_main!(bp);
