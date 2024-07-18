extern crate rewards_proof;

use ark_ec::{models::short_weierstrass::SWCurveConfig, short_weierstrass::Affine};
use ark_secp256k1::Config as SecpConfig;
use ark_secq256k1::Config as SecqConfig;
use ark_std::rand::{prelude::thread_rng, Rng};
use rewards_proof::api::{
    rewards_proof_generation, rewards_proof_setup, rewards_proof_verification,
};

fn rewards_proof_example<C: SWCurveConfig>() {
    let mut rng = thread_rng();

    // set up generators
    let incentive_catalog_size: u64 = 64;
    let (pedersen_gens, bulletproof_gens) =
        rewards_proof_setup::<Affine<C>>(incentive_catalog_size);

    // public value
    let policy_vector: Vec<u64> = (0..incentive_catalog_size)
        .map(|_| rng.gen_range(0..10))
        .collect();

    // private value
    let state: Vec<u64> = (0..incentive_catalog_size)
        .map(|_| rng.gen_range(0..10))
        .collect();

    // reward = <state, policy_vector>
    let reward: u64 = state
        .iter()
        .zip(policy_vector.iter())
        .map(|(x, y)| x.checked_mul(*y))
        .flatten()
        .sum();

    println!("Policy vector: {:?}", policy_vector);
    println!("State: {:?}", state);
    println!("Reward: {:?}", reward);

    // represent state and policy vector as scalar values
    let state_scalar: Vec<C::ScalarField> = state
        .clone()
        .into_iter()
        .map(|u64_value| C::ScalarField::from(u64_value))
        .collect();

    let policy_vector_scalar: Vec<C::ScalarField> = policy_vector
        .clone()
        .into_iter()
        .map(|u64_value| C::ScalarField::from(u64_value))
        .collect();

    // generate rewards proof
    let (range_proof, linear_proof, range_comm, linear_comm) = rewards_proof_generation::<Affine<C>>(
        pedersen_gens.clone(),
        bulletproof_gens.clone(),
        reward,
        state_scalar,
        policy_vector_scalar.clone(),
        incentive_catalog_size,
    );

    // verify rewards proof
    if rewards_proof_verification::<Affine<C>>(
        &pedersen_gens,
        &bulletproof_gens,
        range_proof,
        range_comm,
        linear_proof,
        policy_vector_scalar,
        linear_comm,
    ) {
        println!("Rewards proof verification successfull!");
    } else {
        println!("Rewards proof verification failed!");
    }
}

fn main() {
    // Rewards proof with sec(p)256k1
    rewards_proof_example::<SecpConfig>();
    // Rewards proof with sec(q)256k1
    rewards_proof_example::<SecqConfig>();
}
