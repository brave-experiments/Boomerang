#![allow(non_snake_case)]
use ark_std::UniformRand;
use criterion::BenchmarkId;
use criterion::{criterion_group, criterion_main, Criterion};

// Code below copied from ../tests/r1cs.rs
//
// Ideally we wouldn't duplicate it, but AFAIK criterion requires a
// seperate benchmark harness, while the test code uses a different
// test harness, so I (hdevalence) just copied the code over.  It
// should not be edited here.  In the future it would be good if
// someone wants to figure a way to use #[path] attributes or
// something to avoid the duplication.

use ark_bulletproofs::r1cs::*;
use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_secq256k1::{Affine, Fr};
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

/// A proof-of-shuffle.
struct ShuffleProof(R1CSProof<Affine>);

impl ShuffleProof {
    fn gadget<CS: RandomizableConstraintSystem<Fr>>(
        cs: &mut CS,
        x: Vec<Variable<Fr>>,
        y: Vec<Variable<Fr>>,
    ) -> Result<(), R1CSError> {
        assert_eq!(x.len(), y.len());
        let k = x.len();

        if k == 1 {
            cs.constrain(y[0] - x[0]);
            return Ok(());
        }

        cs.specify_randomized_constraints(move |cs| {
            let z = cs.challenge_scalar(b"shuffle challenge");

            // Make last x multiplier for i = k-1 and k-2
            let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);

            // Make multipliers for x from i == [0, k-3]
            let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
                o
            });

            // Make last y multiplier for i = k-1 and k-2
            let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

            // Make multipliers for y from i == [0, k-3]
            let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
                let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
                o
            });

            // Constrain last x mul output and last y mul output to be equal
            cs.constrain(first_mulx_out - first_muly_out);

            Ok(())
        })
    }
}

impl ShuffleProof {
    /// Attempt to construct a proof that `output` is a permutation of `input`.
    ///
    /// Returns a tuple `(proof, input_commitments || output_commitments)`.
    pub fn prove<R: CryptoRng + RngCore>(
        prng: &mut R,
        pc_gens: &PedersenGens<Affine>,
        bp_gens: &BulletproofGens<Affine>,
        transcript: &mut Transcript,
        input: &[Fr],
        output: &[Fr],
    ) -> Result<(ShuffleProof, Vec<Affine>, Vec<Affine>), R1CSError> {
        // Apply a domain separator with the shuffle parameters to the transcript
        // XXX should this be part of the gadget?
        let k = input.len();
        transcript.append_message(b"dom-sep", b"ShuffleProof");
        transcript.append_u64(b"k", k as u64);

        let mut prover = Prover::new(pc_gens, transcript);

        let (input_commitments, input_vars): (Vec<_>, Vec<_>) = input
            .iter()
            .map(|v| prover.commit(*v, Fr::rand(prng)))
            .unzip();

        let (output_commitments, output_vars): (Vec<_>, Vec<_>) = output
            .iter()
            .map(|v| prover.commit(*v, Fr::rand(prng)))
            .unzip();

        ShuffleProof::gadget(&mut prover, input_vars, output_vars)?;

        let proof = prover.prove(prng, bp_gens)?;

        Ok((ShuffleProof(proof), input_commitments, output_commitments))
    }
}

impl ShuffleProof {
    /// Attempt to verify a `ShuffleProof`.
    pub fn verify(
        &self,
        pc_gens: &PedersenGens<Affine>,
        bp_gens: &BulletproofGens<Affine>,
        transcript: &mut Transcript,
        input_commitments: &[Affine],
        output_commitments: &[Affine],
    ) -> Result<(), R1CSError> {
        // Apply a domain separator with the shuffle parameters to the transcript
        // XXX should this be part of the gadget?
        let k = input_commitments.len();
        transcript.append_message(b"dom-sep", b"ShuffleProof");
        transcript.append_u64(b"k", k as u64);

        let mut verifier = Verifier::new(transcript);

        let input_vars: Vec<_> = input_commitments
            .iter()
            .map(|V| verifier.commit(*V))
            .collect();

        let output_vars: Vec<_> = output_commitments
            .iter()
            .map(|V| verifier.commit(*V))
            .collect();

        ShuffleProof::gadget(&mut verifier, input_vars, output_vars)?;

        verifier.verify(&self.0, pc_gens, bp_gens)
    }
}

// End of copied code.

/// Binary logarithm of maximum shuffle size.
const LG_MAX_SHUFFLE_SIZE: usize = 10;
/// Maximum shuffle size to benchmark.
const MAX_SHUFFLE_SIZE: usize = 1 << LG_MAX_SHUFFLE_SIZE;

fn bench_kshuffle_prove(c: &mut Criterion) {
    // Construct Bulletproof generators externally
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2 * MAX_SHUFFLE_SIZE, 1);

    let mut group = c.benchmark_group("k-shuffle proof creation");
    for size in (1..=LG_MAX_SHUFFLE_SIZE).map(|i| 1 << i) {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, k| {
            // Generate inputs and outputs to kshuffle
            let mut rng = rand::thread_rng();
            let (min, max) = (0u64, u64::MAX);
            let input: Vec<Fr> = (0..*k).map(|_| Fr::from(rng.gen_range(min..max))).collect();
            let mut output = input.clone();
            output.shuffle(&mut rand::thread_rng());

            // Make kshuffle proof
            b.iter(|| {
                let mut prover_transcript = Transcript::new(b"ShuffleBenchmark");
                let mut rng = rand::thread_rng();
                ShuffleProof::prove(
                    &mut rng,
                    &pc_gens,
                    &bp_gens,
                    &mut prover_transcript,
                    &input,
                    &output,
                )
                .unwrap();
            });
        });
    }
}

criterion_group! {
    name = kshuffle_prove;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    config = Criterion::default().sample_size(10);
    targets =
    bench_kshuffle_prove,
}

fn bench_kshuffle_verify(c: &mut Criterion) {
    // Construct Bulletproof generators externally
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2 * MAX_SHUFFLE_SIZE, 1);

    let mut group = c.benchmark_group("k-shuffle proof verification");
    for size in (1..=LG_MAX_SHUFFLE_SIZE).map(|i| 1 << i) {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, k| {
            // Generate the proof in its own scope to prevent reuse of
            // prover variables by the verifier
            let (proof, input_commitments, output_commitments) = {
                // Generate inputs and outputs to kshuffle
                let mut rng = rand::thread_rng();
                let (min, max) = (0u64, u64::MAX);
                let input: Vec<Fr> = (0..*k).map(|_| Fr::from(rng.gen_range(min..max))).collect();
                let mut output = input.clone();
                output.shuffle(&mut rand::thread_rng());

                let mut prover_transcript = Transcript::new(b"ShuffleBenchmark");

                ShuffleProof::prove(
                    &mut rng,
                    &pc_gens,
                    &bp_gens,
                    &mut prover_transcript,
                    &input,
                    &output,
                )
                .unwrap()
            };

            // Verify kshuffle proof
            b.iter(|| {
                let mut verifier_transcript = Transcript::new(b"ShuffleBenchmark");
                proof
                    .verify(
                        &pc_gens,
                        &bp_gens,
                        &mut verifier_transcript,
                        &input_commitments,
                        &output_commitments,
                    )
                    .unwrap();
            })
        });
    }
}

criterion_group! {
    name = kshuffle_verify;
    // Lower the sample size to run faster; larger shuffle sizes are
    // long so we're not microbenchmarking anyways.
    config = Criterion::default().sample_size(10);
    targets =
    bench_kshuffle_verify,
}

criterion_main!(kshuffle_prove, kshuffle_verify);
