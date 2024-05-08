use ark_bulletproofs::{inner_product, BulletproofGens, LinearProof, PedersenGens, RangeProof};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::prelude::thread_rng;
use core::iter;
use merlin::Transcript;
use std::vec;

#[derive(Debug)]
pub enum RewardsProofError {
    /// This error occurs when the commitments cannot be deserialized.
    #[cfg_attr(feature = "std", error("Commitments cannot be deserialized."))]
    CommitmentsDeserializationError,
}

pub fn rewards_proof_setup<C>(
    incentive_catalog_size: u64,
) -> (Vec<PedersenGens<C>>, Vec<BulletproofGens<C>>)
where
    C: AffineRepr,
{
    // Generate generators for the range proof
    let (ps_gen, bp_gen) = setup(64);
    // Generate generators for the linear proof
    let (ps_gen_lin, bp_gen_lin) = setup(incentive_catalog_size as usize);

    let pedersen_gens = vec![ps_gen, ps_gen_lin];
    let bulletproof_gens = vec![bp_gen, bp_gen_lin];
    (pedersen_gens, bulletproof_gens)
}

/// Generates proofs and commitments for the entire rewards proof
pub fn rewards_proof_generation<C>(
    pedersen_gens: Vec<PedersenGens<C>>,
    bulletproof_gens: Vec<BulletproofGens<C>>,
    value: u64,
    private_value: Vec<C::ScalarField>,
    public_value: Vec<C::ScalarField>,
    incentive_catalog_size: u64,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)
where
    C: AffineRepr,
{
    let limit_range_proof: usize = 16; // param?

    // Generate range proof
    let (range_proof, range_proof_commitments) = range_proof::<C>(
        &pedersen_gens.first().unwrap(),
        &bulletproof_gens.first().unwrap(),
        value,
        limit_range_proof,
    );

    // Generate linear proof
    let (linear_proof, linear_proof_commitments) = linear_proof::<C>(
        &pedersen_gens.last().unwrap(),
        &bulletproof_gens.last().unwrap(),
        private_value.clone(),
        public_value.clone(),
        incentive_catalog_size as usize,
    );

    // Serialize proofs
    let mut rp = Vec::new();
    range_proof.serialize_compressed(&mut rp).unwrap();
    let mut lp = Vec::new();
    linear_proof.serialize_compressed(&mut lp).unwrap();

    // Serialize commitments
    let mut rp_com = Vec::new();
    range_proof_commitments
        .serialize_compressed(&mut rp_com)
        .unwrap();
    let mut lp_com = Vec::new();
    linear_proof_commitments
        .serialize_compressed(&mut lp_com)
        .unwrap();

    (rp, lp, rp_com, lp_com)
}

/// Verifies the rewards proofs
pub fn rewards_proof_verification<C>(
    pedersen_gens: &Vec<PedersenGens<C>>,
    bulletproof_gens: &Vec<BulletproofGens<C>>,
    range_proof: Vec<u8>,
    range_proof_commitments: Vec<u8>,
    linear_proof: Vec<u8>,
    public_value: Vec<C::ScalarField>,
    linear_proof_commitments: Vec<u8>,
) -> bool
where
    C: AffineRepr,
{
    let limit_range_proof: usize = 16; // param?

    // Deserialize range proof and commitments
    let r_proof = RangeProof::<C>::deserialize_compressed(&*range_proof).unwrap();
    let r_proof_commitments =
        RangeProofCommitments::deserialize_compressed(&*range_proof_commitments).unwrap();

    // Verify range proof
    if !range_verify(
        &pedersen_gens.first().unwrap(),
        &bulletproof_gens.first().unwrap(),
        r_proof,
        r_proof_commitments,
        limit_range_proof,
    ) {
        return false;
    }

    // Deserialise linear proof
    let l_proof = LinearProof::<C>::deserialize_compressed(&*linear_proof).unwrap();
    let l_proof_commitments =
        LinearProofCommitments::deserialize_compressed(&*linear_proof_commitments).unwrap();

    // Verify linear proof
    if !linear_verify(l_proof, public_value, l_proof_commitments) {
        return false;
    }

    return true;
}

/// Verifies the rewards proofs
pub fn rewards_proof_verification_multiple<C>(
    pedersen_gens: &Vec<PedersenGens<C>>,
    bulletproof_gens: &Vec<BulletproofGens<C>>,
    range_proof: Vec<Vec<u8>>,
    range_proof_commitments: Vec<Vec<u8>>,
    linear_proof: Vec<Vec<u8>>,
    public_value: Vec<C::ScalarField>,
    linear_proof_commitments: Vec<Vec<u8>>,
    number_of_proofs: usize,
) -> bool
where
    C: AffineRepr,
{
    for i in 0..number_of_proofs {
        // verify individual range proofs
        let result = rewards_proof_verification::<C>(
            &pedersen_gens,
            &bulletproof_gens,
            range_proof[i].clone(),
            range_proof_commitments[i].clone(),
            linear_proof[i].clone(),
            public_value.clone(),
            linear_proof_commitments[i].clone(),
        );
        if result == false {
            panic!("Verifying {}'th rewards proof failed!", i);
        }
    }
    return true;
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct LinearProofCommitments<C: AffineRepr> {
    g: Vec<C>,
    f: C,
    b: C,
    c: C,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct RangeProofCommitments<C: AffineRepr> {
    commitment: C,
}

/// Setup for Pedersen Generators and BulletProofs Generators
fn setup<C>(gen_capacity: usize) -> (PedersenGens<C>, BulletproofGens<C>)
where
    C: AffineRepr,
{
    let pedersen_generators = PedersenGens::default();
    let bulletproof_generators = BulletproofGens::new(gen_capacity, 1);
    (pedersen_generators, bulletproof_generators)
}

/// Generates a proof and the commitments for a range proof
fn range_proof<C>(
    ps_gen: &PedersenGens<C>,
    bp_gen: &BulletproofGens<C>,
    value: u64,
    n: usize,
) -> (RangeProof<C>, RangeProofCommitments<C>)
where
    C: AffineRepr,
{
    let mut rng = thread_rng();
    let blinding = C::ScalarField::rand(&mut rng);

    let mut prover_transcript = Transcript::new(b"rangeproof");
    let (proof, commitments) = RangeProof::prove_single(
        &bp_gen,
        &ps_gen,
        &mut prover_transcript,
        value,
        &blinding,
        n,
    )
    .expect("Error when creating rangeproof");
    let proof_commitments: RangeProofCommitments<C> = RangeProofCommitments::<C> {
        commitment: commitments,
    };

    (proof, proof_commitments)
}

/// Verifies a range proof
fn range_verify<C>(
    ps_gen: &PedersenGens<C>,
    bp_gen: &BulletproofGens<C>,
    proof: RangeProof<C>,
    commitments: RangeProofCommitments<C>,
    n: usize,
) -> bool
where
    C: AffineRepr,
{
    let mut verifier_transcript = Transcript::new(b"rangeproof");
    proof
        .verify_single(
            &bp_gen,
            &ps_gen,
            &mut verifier_transcript,
            &commitments.commitment,
            n,
        )
        .is_ok()
}

/// Generates a linear proof
fn linear_proof<C>(
    ps_gen: &PedersenGens<C>,
    bp_gen: &BulletproofGens<C>,
    private_value: Vec<C::ScalarField>,
    public_value: Vec<C::ScalarField>,
    n: usize,
) -> (LinearProof<C>, LinearProofCommitments<C>)
where
    C: AffineRepr,
{
    let mut rng = thread_rng();
    let r = C::ScalarField::rand(&mut rng);

    let g: Vec<C> = bp_gen.share(0).G(n).cloned().collect();
    let f = ps_gen.B;
    let b = ps_gen.B_blinding;

    // C = <a, G> + r * B + <a, b> * F
    let result_inner_product = inner_product(&private_value, &public_value);
    let c = C::Group::msm(
        g.iter()
            .chain(Some(&b))
            .chain(iter::once(&f))
            .copied()
            .collect::<Vec<C>>()
            .as_slice(),
        private_value
            .iter()
            .chain(iter::once(&r))
            .chain(iter::once(&result_inner_product))
            .copied()
            .collect::<Vec<C::ScalarField>>()
            .as_slice(),
    )
    .unwrap()
    .into();

    let mut prover_transcript = Transcript::new(b"linear proof");
    let proof = LinearProof::create(
        &mut prover_transcript,
        &mut rng,
        &c,
        r,
        private_value,
        public_value,
        g.clone(),
        &f,
        &b,
    )
    .expect("Error creating linear proof");
    let linear_commitments: LinearProofCommitments<C> = LinearProofCommitments::<C> {
        g: g,
        f: f,
        b: b,
        c: c,
    };

    (proof, linear_commitments)
}

/// Verifies a linear proof
fn linear_verify<C>(
    proof: LinearProof<C>,
    public_value: Vec<C::ScalarField>,
    commitments: LinearProofCommitments<C>,
) -> bool
where
    C: AffineRepr,
{
    let mut verifier_transcript = Transcript::new(b"linear proof");
    proof
        .verify(
            &mut verifier_transcript,
            &commitments.c,
            &commitments.g,
            &commitments.f,
            &commitments.b,
            public_value,
        )
        .is_ok()
}
