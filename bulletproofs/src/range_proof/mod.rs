#![allow(non_snake_case)]

use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    iter,
    ops::{AddAssign, Neg},
    rand::{CryptoRng, RngCore},
    vec,
    vec::Vec,
    One, Zero,
};

use merlin::Transcript;

use crate::errors::ProofError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::inner_product_proof::InnerProductProof;
use crate::transcript::TranscriptProtocol;
use crate::util;

// Modules for MPC protocol

pub mod dealer;
pub mod messages;
pub mod party;

/// The `RangeProof` struct represents a proof that one or more values
/// are in a range.
///
/// The `RangeProof` struct contains functions for creating and
/// verifying aggregated range proofs.  The single-value case is
/// implemented as a special case of aggregated range proofs.
///
/// The bitsize of the range, as well as the list of commitments to
/// the values, are not included in the proof, and must be known to
/// the verifier.
///
/// This implementation requires that both the bitsize `n` and the
/// aggregation size `m` be powers of two, so that `n = 8, 16, 32, 64`
/// and `m = 1, 2, 4, 8, 16, ...`.  Note that the aggregation size is
/// not given as an explicit parameter, but is determined by the
/// number of values or commitments passed to the prover or verifier.
///
/// # Note
///
/// For proving, these functions run the multiparty aggregation
/// protocol locally.  That API is exposed in the [`aggregation`](::range_proof_mpc)
/// module and can be used to perform online aggregation between
/// parties without revealing secret values to each other.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RangeProof<G: AffineRepr> {
    /// Commitment to the bits of the value
    A: G,
    /// Commitment to the blinding factors
    S: G,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    T_1: G,
    /// Commitment to the \\(t_2\\) coefficient of \\( t(x) \\)
    T_2: G,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    t_x: G::ScalarField,
    /// Blinding factor for the synthetic commitment to \\(t(x)\\)
    t_x_blinding: G::ScalarField,
    /// Blinding factor for the synthetic commitment to the inner-product arguments
    e_blinding: G::ScalarField,
    /// Proof data for the inner-product argument.
    ipp_proof: InnerProductProof<G>,
}

impl<G: AffineRepr> RangeProof<G> {
    /// Create a rangeproof for a given pair of value `v` and
    /// blinding scalar `v_blinding`.
    /// This is a convenience wrapper around [`RangeProof::prove_multiple`].
    pub fn prove_single_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        v: u64,
        v_blinding: &G::ScalarField,
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof<G>, G), ProofError> {
        let (p, Vs) = RangeProof::prove_multiple_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            &[v],
            &[*v_blinding],
            n,
            rng,
        )?;
        Ok((p, Vs[0]))
    }

    /// Create a rangeproof for a given pair of value `v` and
    /// blinding scalar `v_blinding`.
    /// This is a convenience wrapper around [`RangeProof::prove_single_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn prove_single(
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        v: u64,
        v_blinding: &G::ScalarField,
        n: usize,
    ) -> Result<(RangeProof<G>, G), ProofError> {
        RangeProof::prove_single_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            v,
            v_blinding,
            n,
            &mut ark_std::rand::thread_rng(),
        )
    }

    /// Create a rangeproof for a set of values.
    pub fn prove_multiple_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        values: &[u64],
        blindings: &[G::ScalarField],
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof<G>, Vec<G>), ProofError> {
        use self::dealer::*;
        use self::party::*;

        if values.len() != blindings.len() {
            return Err(ProofError::WrongNumBlindingFactors);
        }

        let dealer = Dealer::new(bp_gens, pc_gens, transcript, n, values.len())?;

        let parties: Vec<_> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, &v_blinding)| Party::new(bp_gens, pc_gens, v, v_blinding, n))
            // Collect the iterator of Results into a Result<Vec>, then unwrap it
            .collect::<Result<Vec<_>, _>>()?;

        let (parties, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                p.assign_position_with_rng(j, rng)
                    .expect("We already checked the parameters, so this should never happen")
            })
            .unzip();

        let value_commitments: Vec<_> = bit_commitments.iter().map(|c| c.V_j).collect();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(bit_commitments)?;

        let (parties, poly_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let (dealer, poly_challenge) = dealer.receive_poly_commitments(poly_commitments)?;

        let proof_shares: Vec<_> = parties
            .into_iter()
            .map(|p| p.apply_challenge(&poly_challenge))
            // Collect the iterator of Results into a Result<Vec>, then unwrap it
            .collect::<Result<Vec<_>, _>>()?;

        let proof = dealer.receive_trusted_shares(&proof_shares)?;

        Ok((proof, value_commitments))
    }

    /// Create a rangeproof for a set of values.
    /// This is a convenience wrapper around [`RangeProof::prove_multiple_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn prove_multiple(
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        values: &[u64],
        blindings: &[G::ScalarField],
        n: usize,
    ) -> Result<(RangeProof<G>, Vec<G>), ProofError> {
        RangeProof::prove_multiple_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            values,
            blindings,
            n,
            &mut ark_std::rand::thread_rng(),
        )
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around `verify_multiple` for the `m=1` case.
    pub fn verify_single_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        V: &G,
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(bp_gens, pc_gens, transcript, &[*V], n, rng)
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around [`RangeProof::verify_single_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn verify_single(
        &self,
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        V: &G,
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_single_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            V,
            n,
            &mut ark_std::rand::thread_rng(),
        )
    }

    /// Verifies an aggregated rangeproof for the given value commitments.
    pub fn verify_multiple_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        value_commitments: &[G],
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        let m = value_commitments.len();

        let scalars = self.compute_verification_scalars_with_rng(
            bp_gens,
            transcript,
            value_commitments,
            n,
            rng,
        )?;

        let mega_check = G::Group::msm(
            &iter::once(self.A)
                .chain(iter::once(self.S))
                .chain(iter::once(self.T_1))
                .chain(iter::once(self.T_2))
                .chain(self.ipp_proof.L_vec.iter().cloned())
                .chain(self.ipp_proof.R_vec.iter().cloned())
                .chain(value_commitments.iter().cloned())
                .chain(iter::once(pc_gens.B_blinding))
                .chain(iter::once(pc_gens.B))
                .chain(bp_gens.G(n, m).copied())
                .chain(bp_gens.H(n, m).copied())
                .collect::<Vec<G>>(),
            &scalars,
        );

        if mega_check.unwrap().is_zero() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
    /// Compute multiexponentiation scalars needed to verify this proofs
    pub fn compute_verification_scalars_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens<G>,
        transcript: &mut Transcript,
        value_commitments: &[G],
        n: usize,
        rng: &mut T,
    ) -> Result<Vec<G::ScalarField>, ProofError> {
        let m = value_commitments.len();

        // First, replay the "interactive" protocol using the proof
        // data to recompute all challenges.
        if !(n == 8 || n == 16 || n == 32 || n == 64) {
            return Err(ProofError::InvalidBitsize);
        }
        if bp_gens.gens_capacity < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if bp_gens.party_capacity < m {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        <Transcript as TranscriptProtocol<G>>::rangeproof_domain_sep(
            transcript, n as u64, m as u64,
        );

        for V in value_commitments.iter() {
            // Allow the commitments to be zero (0 value, 0 blinding)
            // See https://github.com/dalek-cryptography/bulletproofs/pull/248#discussion_r255167177
            transcript.append_point(b"V", V);
        }

        transcript.validate_and_append_point(b"A", &self.A)?;
        transcript.validate_and_append_point(b"S", &self.S)?;

        let y: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"y");
        let z: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"z");
        let zz = z * z;
        let minus_z = z.neg();

        transcript.validate_and_append_point(b"T_1", &self.T_1)?;
        transcript.validate_and_append_point(b"T_2", &self.T_2)?;

        let x = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x");

        <Transcript as TranscriptProtocol<G>>::append_scalar(transcript, b"t_x", &self.t_x);
        <Transcript as TranscriptProtocol<G>>::append_scalar(
            transcript,
            b"t_x_blinding",
            &self.t_x_blinding,
        );
        <Transcript as TranscriptProtocol<G>>::append_scalar(
            transcript,
            b"e_blinding",
            &self.e_blinding,
        );

        let w: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"w");

        // Challenge value for batching statements to be verified
        let c = G::ScalarField::rand(rng);

        let (mut x_sq, mut x_inv_sq, s) = self.ipp_proof.verification_scalars(n * m, transcript)?;
        let s_inv = s.iter().rev();

        let a: G::ScalarField = self.ipp_proof.a;
        let b: G::ScalarField = self.ipp_proof.b;

        // Construct concat_z_and_2, an iterator of the values of
        // z^0 * \vec(2)^n || z^1 * \vec(2)^n || ... || z^(m-1) * \vec(2)^n
        let powers_of_2: Vec<G::ScalarField> = util::exp_iter::<G>(G::ScalarField::from(2u64))
            .take(n)
            .collect();
        let concat_z_and_2: Vec<G::ScalarField> = util::exp_iter::<G>(z)
            .take(m)
            .flat_map(|exp_z| powers_of_2.iter().map(move |exp_2| *exp_2 * exp_z))
            .collect();

        let mut g: Vec<G::ScalarField> = s.iter().map(|s_i| minus_z - a * s_i).collect();
        let mut h: Vec<G::ScalarField> = s_inv
            .zip(util::exp_iter::<G>(y.inverse().unwrap()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b * s_i_inv))
            .collect();

        let mut value_commitment_scalars: Vec<G::ScalarField> = util::exp_iter::<G>(z)
            .take(m)
            .map(|z_exp| c * zz * z_exp)
            .collect();

        let tmp: G::ScalarField = delta::<G>(n, m, &y, &z);
        let basepoint_scalar: G::ScalarField = w * (self.t_x - a * b) + c * (tmp - self.t_x);

        let mut scalars = vec![
            G::ScalarField::one(), // A
            x,                     // S
            c * x,                 // T_1
            c * x * x,
        ]; //T_2
        scalars.append(&mut x_sq); // L_vec TODO avoid append, better chaining iterators
        scalars.append(&mut x_inv_sq); // R_vec
        scalars.append(&mut value_commitment_scalars); //Value com
        scalars.push(self.e_blinding.neg() - c * self.t_x_blinding); // B_blinding
        scalars.push(basepoint_scalar); // B
        scalars.append(&mut g); // G_vec
        scalars.append(&mut h); // H_vec
        Ok(scalars)
    }

    /// Verifies multiple aggregated rangeproofs with a single multiexponentiation
    pub fn batch_verify<T: RngCore + CryptoRng>(
        rng: &mut T,
        proofs: &[&RangeProof<G>],
        transcripts: &mut [Transcript],
        value_commitments: &[&[G]],
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        n: usize,
    ) -> Result<(), ProofError> {
        let mut all_scalars = vec![];
        let mut random_scalars = vec![];
        let mut max_m = 0;
        for ((proof, transcript), value_commitment) in proofs
            .iter()
            .zip(transcripts.iter_mut())
            .zip(value_commitments.iter())
        {
            let instance_scalars = proof.compute_verification_scalars_with_rng(
                bp_gens,
                transcript,
                value_commitment,
                n,
                rng,
            )?;
            let mut rng = transcript
                .build_rng()
                .finalize(&mut ark_std::rand::thread_rng());
            random_scalars.push(G::ScalarField::rand(&mut rng));
            all_scalars.push((instance_scalars, value_commitment.len()));
        }
        let mut all_scaled_scalars = vec![];
        for ((scalars, m_i), rand_scalar) in all_scalars.iter().zip(random_scalars.iter()) {
            let scaled_scalars: Vec<G::ScalarField> =
                scalars.iter().map(|s| *s * rand_scalar).collect();
            all_scaled_scalars.push((scaled_scalars, *m_i));
            if *m_i > max_m {
                max_m = *m_i;
            }
        }
        let grouped_scalars = Self::group_scalars(all_scaled_scalars.as_slice(), n, max_m).to_vec();

        let mut elems = vec![];
        for (proof, value_commitments) in proofs.iter().zip(value_commitments) {
            elems.push(proof.A);
            elems.push(proof.S);
            elems.push(proof.T_1);
            elems.push(proof.T_2);
            for L in proof.ipp_proof.L_vec.iter() {
                elems.push(*L);
            }
            for R in proof.ipp_proof.R_vec.iter() {
                elems.push(*R);
            }
            for V in value_commitments.iter() {
                elems.push(*V)
            }
        }
        elems.push(pc_gens.B_blinding);
        elems.push(pc_gens.B);
        for G in bp_gens.G(n, max_m) {
            elems.push(*G);
        }
        for H in bp_gens.H(n, max_m) {
            elems.push(*H);
        }
        let mega_check = G::Group::msm(&elems, &grouped_scalars);
        if !mega_check.unwrap().is_zero() {
            return Err(ProofError::VerificationError);
        }
        Ok(())
    }

    fn group_scalars(
        all_scalars: &[(Vec<G::ScalarField>, usize)],
        n: usize,
        max_m: usize,
    ) -> Vec<G::ScalarField> {
        let mut agg_scalars = vec![];
        let mut b_blind_scalars = G::ScalarField::from(0u8);
        let mut b_scalars = G::ScalarField::from(0u8);
        let mut g_scalars = vec![G::ScalarField::from(0u8); n * max_m];
        let mut h_scalars = vec![G::ScalarField::from(0u8); n * max_m];

        for (instance_scalars, m_i) in all_scalars {
            let N_i = *m_i * n; // size of this instance
            let lgN = (N_i as u64).trailing_zeros() as usize; // size of L and R vecs
                                                              // A,S,T1,T2 (4 elements) and L_vec, R_vec (lgN elemens each) + V (m_i elements)
            let k_i = 4usize + 2usize * lgN + *m_i; // number of elements unique to this instance
            for j in 0..k_i {
                agg_scalars.push(*instance_scalars.get(j).unwrap());
            }
            b_blind_scalars.add_assign(&instance_scalars[k_i]);
            b_scalars.add_assign(&instance_scalars[k_i + 1]);
            for i in k_i + 2..k_i + 2 + N_i {
                g_scalars[i - k_i - 2] += &instance_scalars[i];
                h_scalars[i - k_i - 2] += &instance_scalars[N_i + i];
            }
        }
        agg_scalars.push(b_blind_scalars);
        agg_scalars.push(b_scalars);
        agg_scalars.append(&mut g_scalars);
        agg_scalars.append(&mut h_scalars);

        agg_scalars
    }

    /// Verifies an aggregated rangeproof for the given value commitments.
    /// This is a convenience wrapper around [`RangeProof::verify_multiple_with_rng`],
    /// passing in a threadsafe RNG.
    #[cfg(feature = "std")]
    pub fn verify_multiple(
        &self,
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut Transcript,
        value_commitments: &[G],
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(
            bp_gens,
            pc_gens,
            transcript,
            value_commitments,
            n,
            &mut ark_std::rand::thread_rng(),
        )
    }
}

/// Compute
/// \\[
/// \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
/// \\]
fn delta<G: AffineRepr>(
    n: usize,
    m: usize,
    y: &G::ScalarField,
    z: &G::ScalarField,
) -> G::ScalarField {
    let sum_y = util::sum_of_powers::<G>(y, n * m);
    let sum_2 = util::sum_of_powers::<G>(&G::ScalarField::from(2u64), n);
    let sum_z = util::sum_of_powers::<G>(z, m);

    (*z - *z * z) * sum_y - *z * z * z * sum_2 * sum_z
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::generators::PedersenGens;
    use ark_ff::UniformRand;
    use ark_secq256k1::{Affine, Fr};
    use ark_std::{rand::Rng, vec, vec::Vec, One, Zero};

    #[test]
    fn test_delta() {
        let mut rng = rand::thread_rng();
        let y = Fr::rand(&mut rng);
        let z = Fr::rand(&mut rng);

        // Choose n = 256 to ensure we overflow the group order during
        // the computation, to check that that's done correctly
        let n = 256;

        // code copied from previous implementation
        let z2 = z * z;
        let z3 = z2 * z;
        let mut power_g = Fr::zero();
        let mut exp_y = Fr::one(); // start at y^0 = 1
        let mut exp_2 = Fr::one(); // start at 2^0 = 1
        for _ in 0..n {
            power_g += (z - z2) * exp_y - z3 * exp_2;

            exp_y *= y; // y^i -> y^(i+1)
            exp_2 += exp_2; // 2^i -> 2^(i+1)
        }

        assert_eq!(power_g, delta::<Affine>(n, 1, &y, &z),);
    }

    /// Given a bitsize `n`, test the following:
    ///
    /// 1. Generate `m` random values and create a proof they are all in range;
    /// 2. Serialize to wire format;
    /// 3. Deserialize from wire format;
    /// 4. Verify the proof.
    fn singleparty_create_and_verify_helper(n: usize, m: usize) {
        // Split the test into two scopes, so that it's explicit what
        // data is shared between the prover and the verifier.

        // Use bincode for serialization

        // Both prover and verifier have access to the generators and the proof
        let max_bitsize = 128;
        let max_parties = 8;
        let pc_gens: PedersenGens<Affine> = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        // Prover's scope
        let (proof_bytes, value_commitments) = {
            let mut rng = rand::thread_rng();

            // 0. Create witness data
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min..max)).collect();
            let blindings: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut rng)).collect();

            // 1. Create the proof
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let (proof, value_commitments) = RangeProof::prove_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &values,
                &blindings,
                n,
            )
            .unwrap();

            //let mut tmp = Vec::new();
            //proof.serialize_compressed(&mut tmp).unwrap();

            // 2. Return serialized proof and value commitments
            (proof, value_commitments)
        };

        // Verifier's scope
        {
            // 3. Deserialize
            //let proof: RangeProof<Affine> =
            //    RangeProof::deserialize_compressed(&proof_bytes).unwrap();

            // 4. Verify with the same customization label as above
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

            assert!(proof_bytes
                .verify_multiple(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n)
                .is_ok());
        }
    }

    #[test]
    fn create_simple() {
        let max_bitsize = 128;
        let max_parties = 1;
        let pc_gens: PedersenGens<Affine> = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        // Prover's scope
        let (proof_bytes, value_commitments) = {
            let mut rng = rand::thread_rng();

            // 0. Create witness data
            let (min, max) = (0u64, ((1u128 << 64) - 1) as u64);
            let value: u64 = rng.gen_range(min..max);
            let blinding: Fr = Fr::rand(&mut rng);

            // 1. Create the proof
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let (proof, value_commitments) =
                RangeProof::prove_single(&bp_gens, &pc_gens, &mut transcript, value, &blinding, 64)
                    .unwrap();

            //let mut tmp = Vec::new();
            //proof.serialize_compressed(&mut tmp).unwrap();

            // 2. Return serialized proof and value commitments
            (proof, value_commitments)
        };

        // Verifier's scope
        {
            // 3. Deserialize
            //let proof: RangeProof<Affine> =
            //    RangeProof::deserialize_compressed(&proof_bytes).unwrap();

            // 4. Verify with the same customization label as above
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

            assert!(proof_bytes
                .verify_single(&bp_gens, &pc_gens, &mut transcript, &value_commitments, 64)
                .is_ok());
        }
    }

    #[test]
    fn create_and_verify_n_32_m_1() {
        singleparty_create_and_verify_helper(32, 1);
    }

    #[test]
    fn create_and_verify_n_32_m_2() {
        singleparty_create_and_verify_helper(32, 2);
    }

    #[test]
    fn create_and_verify_n_32_m_4() {
        singleparty_create_and_verify_helper(32, 4);
    }

    #[test]
    fn create_and_verify_n_32_m_8() {
        singleparty_create_and_verify_helper(32, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_1() {
        singleparty_create_and_verify_helper(64, 1);
    }

    #[test]
    fn create_and_verify_n_64_m_2() {
        singleparty_create_and_verify_helper(64, 2);
    }

    #[test]
    fn create_and_verify_n_64_m_4() {
        singleparty_create_and_verify_helper(64, 4);
    }

    #[test]
    fn create_and_verify_n_64_m_8() {
        singleparty_create_and_verify_helper(64, 8);
    }

    #[test]
    fn detect_dishonest_party_during_aggregation() {
        use self::dealer::*;
        use self::party::*;

        use crate::errors::MPCError;

        // Simulate four parties, two of which will be dishonest and use a 64-bit value.
        let m = 4;
        let n = 32;

        let pc_gens: PedersenGens<Affine> = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n, m);

        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

        // Parties 0, 2 are honest and use a 32-bit value
        let v0 = rng.gen::<u32>() as u64;
        let v0_blinding = Fr::rand(&mut rng);
        let party0 = Party::new(&bp_gens, &pc_gens, v0, v0_blinding, n).unwrap();

        let v2 = rng.gen::<u32>() as u64;
        let v2_blinding = Fr::rand(&mut rng);
        let party2 = Party::new(&bp_gens, &pc_gens, v2, v2_blinding, n).unwrap();

        // Parties 1, 3 are dishonest and use a 64-bit value
        let v1 = rng.gen::<u64>();
        let v1_blinding = Fr::rand(&mut rng);
        let party1 = Party::new(&bp_gens, &pc_gens, v1, v1_blinding, n).unwrap();

        let v3 = rng.gen::<u64>();
        let v3_blinding = Fr::rand(&mut rng);
        let party3 = Party::new(&bp_gens, &pc_gens, v3, v3_blinding, n).unwrap();

        let dealer = Dealer::new(&bp_gens, &pc_gens, &mut transcript, n, m).unwrap();

        let (party0, bit_com0) = party0.assign_position(0).unwrap();
        let (party1, bit_com1) = party1.assign_position(1).unwrap();
        let (party2, bit_com2) = party2.assign_position(2).unwrap();
        let (party3, bit_com3) = party3.assign_position(3).unwrap();

        let (dealer, bit_challenge) = dealer
            .receive_bit_commitments(vec![bit_com0, bit_com1, bit_com2, bit_com3])
            .unwrap();

        let (party0, poly_com0) = party0.apply_challenge(&bit_challenge);
        let (party1, poly_com1) = party1.apply_challenge(&bit_challenge);
        let (party2, poly_com2) = party2.apply_challenge(&bit_challenge);
        let (party3, poly_com3) = party3.apply_challenge(&bit_challenge);

        let (dealer, poly_challenge) = dealer
            .receive_poly_commitments(vec![poly_com0, poly_com1, poly_com2, poly_com3])
            .unwrap();

        let share0 = party0.apply_challenge(&poly_challenge).unwrap();
        let share1 = party1.apply_challenge(&poly_challenge).unwrap();
        let share2 = party2.apply_challenge(&poly_challenge).unwrap();
        let share3 = party3.apply_challenge(&poly_challenge).unwrap();

        match dealer.receive_shares(&[share0, share1, share2, share3]) {
            Err(MPCError::MalformedProofShares { bad_shares }) => {
                assert_eq!(bad_shares, vec![1, 3]);
            }
            Err(_) => {
                panic!("Got wrong error type from malformed shares");
            }
            Ok(_) => {
                panic!("The proof was malformed, but it was not detected");
            }
        }
    }

    #[test]
    fn detect_dishonest_dealer_during_aggregation() {
        use self::dealer::*;
        use self::party::*;
        use crate::errors::MPCError;

        // Simulate one party
        let m = 1;
        let n = 32;

        let pc_gens: PedersenGens<Affine> = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n, m);

        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

        let v0 = rng.gen::<u32>() as u64;
        let v0_blinding = Fr::rand(&mut rng);
        let party0 = Party::new(&bp_gens, &pc_gens, v0, v0_blinding, n).unwrap();

        let dealer = Dealer::new(&bp_gens, &pc_gens, &mut transcript, n, m).unwrap();

        // Now do the protocol flow as normal....

        let (party0, bit_com0) = party0.assign_position(0).unwrap();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(vec![bit_com0]).unwrap();

        let (party0, poly_com0) = party0.apply_challenge(&bit_challenge);

        let (_dealer, mut poly_challenge) =
            dealer.receive_poly_commitments(vec![poly_com0]).unwrap();

        // But now simulate a malicious dealer choosing x = 0
        poly_challenge.x = Fr::zero();

        let maybe_share0 = party0.apply_challenge(&poly_challenge);

        assert!(maybe_share0.unwrap_err() == MPCError::MaliciousDealer);
    }
}
