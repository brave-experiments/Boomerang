use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use ark_ec::{models::short_weierstrass::SWCurveConfig, short_weierstrass::Affine};
use ark_secp256k1::Config as SecpConfig;
use ark_std::rand::{prelude::thread_rng, Rng};

use rewards_proof::api::{
    rewards_proof_generation, rewards_proof_setup, rewards_proof_verification,
    rewards_proof_verification_multiple,
};

fn criterion_benchmark(c: &mut Criterion) {
    benchmark_rewardsproof_generation::<SecpConfig>(c);
    benchmark_rewardsproof_verification::<SecpConfig>(c);
    benchmark_rewardsproof_verification_multiple_users::<SecpConfig>(c, 1000, 64);
}

#[allow(dead_code)]
fn benchmark_rewardsproof_generation<C: SWCurveConfig>(c: &mut Criterion) {
    let mut group = c.benchmark_group("rewardsproof gen");

    let mut rng = thread_rng();
    // set measurement time to 10 seconds
    group.measurement_time(Duration::new(10, 0));

    for size in [64, 128, 256].iter() {
        //pre-processing
        let policy_vector: Vec<u64> = (0..*size).map(|_| rng.gen_range(0..10)).collect();
        let policy_vector_scalar: Vec<C::ScalarField> = policy_vector
            .clone()
            .into_iter()
            .map(|u64_value| C::ScalarField::from(u64_value))
            .collect();
        // private value
        let state: Vec<u64> = (0..*size).map(|_| rng.gen_range(0..10)).collect();
        let state_scalar: Vec<C::ScalarField> = state
            .clone()
            .into_iter()
            .map(|u64_value| C::ScalarField::from(u64_value))
            .collect();

        // reward = <state, policy_vector>
        let reward: u64 = state
            .iter()
            .zip(policy_vector.iter())
            .map(|(x, y)| x.checked_mul(*y))
            .flatten()
            .sum();

        // create generators
        let (pedersen_gens, bulletproof_gens) = rewards_proof_setup::<Affine<C>>(*size);

        // generate rewards proof
        group.bench_with_input(BenchmarkId::new("rewardsproof-", size), size, |b, _size| {
            b.iter(|| {
                rewards_proof_generation::<Affine<C>>(
                    pedersen_gens.clone(),
                    bulletproof_gens.clone(),
                    reward,
                    state_scalar.clone(),
                    policy_vector_scalar.clone(),
                    *size,
                );
            })
        });
    }
    group.finish();
}

#[allow(dead_code)]
fn benchmark_rewardsproof_verification<C: SWCurveConfig>(c: &mut Criterion) {
    let mut group = c.benchmark_group("rewardsproof verify");

    let mut rng = thread_rng();
    // set measurement time to 10 seconds
    group.measurement_time(Duration::new(10, 0));

    for size in [64, 128, 256].iter() {
        //pre-processing
        let policy_vector: Vec<u64> = (0..*size).map(|_| rng.gen_range(0..10)).collect();
        let policy_vector_scalar: Vec<C::ScalarField> = policy_vector
            .clone()
            .into_iter()
            .map(|u64_value| C::ScalarField::from(u64_value))
            .collect();
        // private value
        let state: Vec<u64> = (0..*size).map(|_| rng.gen_range(0..10)).collect();
        let state_scalar: Vec<C::ScalarField> = state
            .clone()
            .into_iter()
            .map(|u64_value| C::ScalarField::from(u64_value))
            .collect();

        // reward = <state, policy_vector>
        let reward: u64 = state
            .iter()
            .zip(policy_vector.iter())
            .map(|(x, y)| x.checked_mul(*y))
            .flatten()
            .sum();

        // create variables for linear proof
        let (pedersen_gens, bulletproof_gens) = rewards_proof_setup::<Affine<C>>(*size);

        // generate rewards proof
        let (range_proof, linear_proof, range_comm, linear_comm) =
            rewards_proof_generation::<Affine<C>>(
                pedersen_gens.clone(),
                bulletproof_gens.clone(),
                reward,
                state_scalar,
                policy_vector_scalar.clone(),
                *size,
            );

        // verify rewards proof
        group.bench_with_input(BenchmarkId::new("rangeproof-", size), size, |b, _size| {
            b.iter(|| {
                rewards_proof_verification::<Affine<C>>(
                    &pedersen_gens,
                    &bulletproof_gens,
                    range_proof.clone(),
                    range_comm.clone(),
                    linear_proof.clone(),
                    policy_vector_scalar.clone(),
                    linear_comm.clone(),
                )
            })
        });
    }
    group.finish();
}

#[allow(dead_code)]
fn benchmark_rewardsproof_verification_multiple_users<C: SWCurveConfig>(
    c: &mut Criterion,
    number_of_users: usize,
    incentive_size: usize,
) {
    // preprocessing
    let mut rng = rand::thread_rng();

    let mut pedersen_gens = vec![];
    let mut bulletproof_gens = vec![];

    let mut range_proofs: Vec<Vec<u8>> = vec![];
    let mut range_proof_commitments: Vec<Vec<u8>> = vec![];

    let mut linear_proofs: Vec<Vec<u8>> = vec![];
    let mut linear_proof_commitments: Vec<Vec<u8>> = vec![];

    //pre-processing
    let policy_vector: Vec<u64> = (0..incentive_size).map(|_| rng.gen_range(0..10)).collect();
    let policy_vector_scalar: Vec<C::ScalarField> = policy_vector
        .clone()
        .into_iter()
        .map(|u64_value| C::ScalarField::from(u64_value))
        .collect();
    // private value
    let state: Vec<u64> = (0..incentive_size).map(|_| rng.gen_range(0..10)).collect();
    let state_scalar: Vec<C::ScalarField> = state
        .clone()
        .into_iter()
        .map(|u64_value| C::ScalarField::from(u64_value))
        .collect();

    // reward = <state, policy_vector>
    let reward: u64 = state
        .iter()
        .zip(policy_vector.iter())
        .map(|(x, y)| x.checked_mul(*y))
        .flatten()
        .sum();

    // generate number_of_users proofs
    for _x in 0..number_of_users {
        // create generators
        (pedersen_gens, bulletproof_gens) = rewards_proof_setup::<Affine<C>>(incentive_size as u64);

        // generate rewards proof
        let (range_proof, linear_proof, range_comm, linear_comm) =
            rewards_proof_generation::<Affine<C>>(
                pedersen_gens.clone(),
                bulletproof_gens.clone(),
                reward,
                state_scalar.clone(),
                policy_vector_scalar.clone(),
                incentive_size as u64,
            );

        range_proofs.push(range_proof);
        linear_proofs.push(linear_proof);
        range_proof_commitments.push(range_comm);
        linear_proof_commitments.push(linear_comm);
    }

    let mut group = c.benchmark_group("multiple reward proofs verification");
    group.sample_size(10);
    group.measurement_time(Duration::new(20, 0));
    //group.sampling_mode(criterion::SamplingMode::Flat);

    // verify rewards proofs
    group.bench_function("multiple_reward_proofs", |b| {
        b.iter(|| {
            rewards_proof_verification_multiple::<Affine<C>>(
                &pedersen_gens,
                &bulletproof_gens,
                range_proofs.clone(),
                range_proof_commitments.clone(),
                linear_proofs.clone(),
                policy_vector_scalar.clone(),
                linear_proof_commitments.clone(),
                number_of_users,
            )
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
