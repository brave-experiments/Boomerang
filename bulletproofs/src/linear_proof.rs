#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand};

use merlin::Transcript;

use crate::errors::ProofError;
use crate::inner_product_proof::inner_product;
use crate::transcript::TranscriptProtocol;

/// A linear proof, which is an "lightweight" version of a Bulletproofs inner-product proof
/// Protocol: Section E.3 of [GHL'21](https://eprint.iacr.org/2021/1397.pdf)
///
/// Prove that <a, b> = c where a is secret and b is public.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct LinearProof<G: AffineRepr> {
    pub(crate) L_vec: Vec<G>,
    pub(crate) R_vec: Vec<G>,
    /// A commitment to the base case elements
    pub(crate) S: G,
    /// a_star, corresponding to the base case `a`
    pub(crate) a: G::ScalarField,
    /// r_star, corresponding to the base case `r`
    pub(crate) r: G::ScalarField,
}

impl<G: AffineRepr> LinearProof<G> {
    /// Create a linear proof, a lightweight variant of a Bulletproofs inner-product proof.
    /// This proves that <a, b> = c where a is secret and b is public.
    ///
    /// The lengths of the vectors must all be the same, and must all be either 0 or a power of 2.
    /// The proof is created with respect to the bases \\(G\\).
    pub fn create<R: Rng>(
        transcript: &mut Transcript,
        rng: &mut R,
        // Commitment to witness
        C: &G,
        // Blinding factor for C
        mut r: G::ScalarField,
        // Secret scalar vector a
        mut a_vec: Vec<G::ScalarField>,
        // Public scalar vector b
        mut b_vec: Vec<G::ScalarField>,
        // Generator vector
        mut G_vec: Vec<G>,
        // Pedersen generator F, for committing to the secret value
        F: &G,
        // Pedersen generator B, for committing to the blinding value
        B: &G,
    ) -> Result<LinearProof<G>, ProofError> {
        let mut n = b_vec.len();
        // All of the input vectors must have the same length.
        if G_vec.len() != n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if a_vec.len() != n {
            return Err(ProofError::InvalidInputLength);
        }
        // All of the input vectors must have a length that is a power of two.
        if !n.is_power_of_two() {
            return Err(ProofError::InvalidInputLength);
        }

        // Append all public data to the transcript
        //transcript.innerproduct_domain_sep(n as u64);
        <Transcript as TranscriptProtocol<G>>::innerproduct_domain_sep(transcript, n as u64);
        transcript.append_point(b"C", C);
        for b_i in &b_vec {
            //transcript.append_scalar::<C>(b"b_i", b_i);
            <Transcript as TranscriptProtocol<G>>::append_scalar(transcript, b"b_i", &b_i);
        }
        for G_i in &G_vec {
            transcript.append_point(b"G_i", G_i);
        }
        transcript.append_point(b"F", F);
        transcript.append_point(b"B", B);

        // Create slices G, H, a, b backed by their respective
        // vectors. This lets us reslice as we compress the lengths
        // of the vectors in the main loop below.
        let mut G = &mut G_vec[..];
        let mut a = &mut a_vec[..];
        let mut b = &mut b_vec[..];

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        while n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let s_j = G::ScalarField::rand(rng);
            let t_j = G::ScalarField::rand(rng);

            // L = a_L * G_R + s_j * B + c_L * F
            let L = G::Group::msm(G_R, a_L).unwrap() + (*B) * s_j + (*F) * c_L;

            // R = a_R * G_L + t_j * B + c_R * F
            let R = G::Group::msm(G_L, a_R).unwrap() + (*B) * t_j + (*F) * c_R;

            L_vec.push(L.into());
            R_vec.push(R.into());

            transcript.append_point(b"L", &L.into());
            transcript.append_point(b"R", &R.into());

            //let x_j = transcript.challenge_scalar::<G>(b"x_j");
            let x_j: G::ScalarField = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x_j");
            let x_j_inv = x_j.inverse().unwrap();

            for i in 0..n {
                // a_L = a_L + x_j^{-1} * a_R
                a_L[i] = a_L[i] + x_j_inv * a_R[i];
                // b_L = b_L + x_j * b_R
                b_L[i] = b_L[i] + x_j * b_R[i];
                // G_L = G_L + x_j * G_R
                G_L[i] = (G_L[i] + G_R[i] * x_j).into();
            }
            a = a_L;
            b = b_L;
            G = G_L;
            r = r + x_j * s_j + x_j_inv * t_j;
        }

        let s_star = G::ScalarField::rand(rng);
        let t_star = G::ScalarField::rand(rng);
        let S = (*B) * t_star + (*F) * s_star * b[0] + G[0] * s_star;
        let S = S.into();
        transcript.append_point(b"S", &S);

        //let x_star = transcript.challenge_scalar::<G>(b"x_star");
        let x_star: G::ScalarField = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x_star");
        let a_star = s_star + x_star * a[0];
        let r_star = t_star + x_star * r;

        Ok(LinearProof {
            L_vec,
            R_vec,
            S,
            a: a_star,
            r: r_star,
        })
    }

    /// Verify a linear proof
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        // Commitment to witness
        C: &G,
        // Generator vector
        G: &[G],
        // Pedersen generator F, for committing to the secret value
        F: &G,
        // Pedersen generator B, for committing to the blinding value
        B: &G,
        // Public scalar vector b
        b_vec: Vec<G::ScalarField>,
    ) -> Result<(), ProofError> {
        let n = b_vec.len();
        if G.len() != n {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        // Append all public data to the transcript
        //transcript.innerproduct_domain_sep(n as u64);
        <Transcript as TranscriptProtocol<G>>::innerproduct_domain_sep(transcript, n as u64);
        transcript.append_point(b"C", C);
        for b_i in &b_vec {
            //transcript.append_scalar::<G>(b"b_i", b_i);
            <Transcript as TranscriptProtocol<G>>::append_scalar(transcript, b"b_i", &b_i);
        }
        for G_i in G {
            transcript.append_point(b"G_i", G_i);
        }
        transcript.append_point(b"F", F);
        transcript.append_point(b"B", B);

        let (x_vec, x_inv_vec, b_0) = self.verification_scalars(n, transcript, b_vec)?;
        transcript.append_point(b"S", &self.S);
        //let x_star = transcript.challenge_scalar::<G>(b"x_star");
        let x_star: G::ScalarField = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x_star");

        // L_R_factors = sum_{j=0}^{l-1} (x_j * L_j + x_j^{-1} * R_j)
        //
        // Note: in GHL'21 the verification equation is incorrect (as of 05/03/22), with x_j and x_j^{-1} reversed.
        // (Incorrect paper equation: sum_{j=0}^{l-1} (x_j^{-1} * L_j + x_j * R_j) )
        let L_R_factors = G::Group::msm(&self.L_vec, &x_vec).unwrap()
            + G::Group::msm(&self.R_vec, &x_inv_vec).unwrap();

        // This is an optimized way to compute the base case G (G_0 in the paper):
        // G_0 = sum_{i=0}^{2^{l-1}} (x<i> * G_i)
        let s = self.subset_product(n, x_vec);
        let G_0 = G::Group::msm(&G, &s).unwrap();

        // This matches the verification equation:
        // S == r_star * B + a_star * b_0 * F
        //      - x_star * (C + sum_{j=0}^{l-1} (x_j * L_j + x_j^{-1} * R_j))
        //      + a_star * sum_{i=0}^{2^{l-1}} (x<i> * G_i)
        //
        // Where L_R_factors = sum_{j=0}^{l-1} (x_j * L_j + x_j^{-1} * R_j)
        // and G_0 = sum_{i=0}^{2^{l-1}} (x<i> * G_i)
        let expect_S =
            (*B) * self.r + (*F) * self.a * b_0 - (*C + L_R_factors) * x_star + G_0 * self.a;

        if expect_S.into() == self.S {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Computes the vector of challenge scalars \\([x\_{i}]\\), and its inverse \\([x\_{i}^{-1}]\\)
    /// for combined multiscalar multiplication in a parent protocol.
    /// Also computes \\(b_0\\) which is the base case for public vector \\(b\\).
    ///
    /// The verifier must provide the input length \\(n\\) explicitly to avoid unbounded allocation.
    pub(crate) fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
        mut b_vec: Vec<G::ScalarField>,
    ) -> Result<(Vec<G::ScalarField>, Vec<G::ScalarField>, G::ScalarField), ProofError> {
        let lg_n = self.L_vec.len();
        if lg_n >= 32 {
            // 4 billion multiplications should be enough for anyone
            // and this check prevents overflow in 1<<lg_n below.
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        // 1. Recompute x_k,...,x_1 based on the proof transcript
        // 2. Generate b_0 from the public vector b
        let mut n_mut = n;
        let mut b = &mut b_vec[..];
        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            transcript.validate_and_append_point(b"L", L)?;
            transcript.validate_and_append_point(b"R", R)?;
            //let x_j = transcript.challenge_scalar::<G>(b"x_j");
            let x_j: G::ScalarField = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x_j");
            challenges.push(x_j);
            n_mut = n_mut / 2;
            let (b_L, b_R) = b.split_at_mut(n_mut);
            for i in 0..n_mut {
                b_L[i] = b_L[i] + x_j * b_R[i];
            }
            b = b_L;
        }

        // 3. Compute the challenge inverses: 1/x_k, ..., 1/x_1
        let challenges_inv = challenges.iter().map(|x| x.inverse().unwrap()).collect();

        Ok((challenges, challenges_inv, b[0]))
    }

    /// Compute the subset-products of \\(x_j\\) inductively:
    /// for i = 1..n, \\(s_i = product_(j=1^{log_2(n)}) x_j ^ b(i,j)\\)
    /// where \\(b(i,j)\\) = 1 if the jth bit of (i-1) is 1, and 0 otherwise.
    /// In GHL'21 this is referred to as the subset-product \\(x<i>\\).
    ///
    /// Note that this is different from the Bulletproofs \\(s_i\\) generation,
    /// where \\(b(i, j)\\) = 1 if the jth bit of (i-1) is 1, and -1 otherwise.
    fn subset_product(&self, n: usize, challenges: Vec<G::ScalarField>) -> Vec<G::ScalarField> {
        let lg_n = self.L_vec.len();

        let mut s = Vec::with_capacity(n);
        s.push(G::ScalarField::one());
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [x_k,...,x_1],
            // so x_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let x_lg_i = challenges[(lg_n - 1) - lg_i];
            s.push(s[i - k] * x_lg_i);
        }

        s
    }
}

#[cfg(test)]
mod tests {
    // TODO fix me
    /*use super::*;

    use ark_pallas::Affine;
    use ark_std::UniformRand;

    type F = <Affine as AffineRepr>::ScalarField;

    fn test_helper(n: usize) {
        //let mut rng = rand::thread_rng();
        use ark_std::rand::{prelude::StdRng, Rng, SeedableRng};
        let seed = [
            1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let mut rng = StdRng::from_seed(seed);

        use crate::generators::{BulletproofGens, PedersenGens};
        let bp_gens = BulletproofGens::<Affine>::new(n, 1);
        let G: Vec<_> = bp_gens.share(0).G(n).cloned().collect();

        let pedersen_gens = PedersenGens::<Affine>::default();
        let F = pedersen_gens.B;
        let B = pedersen_gens.B_blinding;

        // a and b are the vectors for which we want to prove c = <a,b>
        // a is a private vector, b is a public vector
        let a: Vec<_> = (0..n).map(|_| <Affine as AffineRepr>::ScalarField::random(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| <Affine as AffineRepr>::ScalarField::random(&mut rng)).collect();

        let mut prover_transcript = Transcript::new(b"linearprooftest");

        // C = <a, G> + r * B + <a, b> * F
        let r = <Affine as AffineRepr>::ScalarField::random(&mut rng);
        let c = inner_product(&a, &b);
        let C = <Affine as AffineRepr>::vartime_multiscalar_mul(
            a.iter().chain(iter::once(&r)).chain(iter::once(&c)),
            G.iter().chain(Some(&B)).chain(iter::once(&F)),
        )
        .compress();

        let proof = LinearProof::create(
            &mut prover_transcript,
            &mut rng,
            &C,
            r,
            a,
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"linearprooftest");
        assert!(proof
            .verify(&mut verifier_transcript, &C, &G, &F, &B, b.clone())
            .is_ok());

        // Test serialization and deserialization
        let serialized_proof = proof.to_bytes();
        assert_eq!(proof.serialized_size(), serialized_proof.len());

        let deserialized_proof = LinearProof::from_bytes(&serialized_proof).unwrap();
        let mut serde_verifier_transcript = Transcript::new(b"linearprooftest");
        assert!(deserialized_proof
            .verify(&mut serde_verifier_transcript, &C, &G, &F, &B, b)
            .is_ok());
    }

    #[test]
    fn test_linear_proof_base() {
        test_helper(1);
    }

    #[test]
    fn test_linear_proof_16() {
        test_helper(16);
    }

    #[test]
    fn test_linear_proof_32() {
        test_helper(32);
    }

    #[test]
    fn test_linear_proof_64() {
        test_helper(64);
    }*/
}
