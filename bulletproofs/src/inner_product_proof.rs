#![allow(non_snake_case)]

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{batch_inversion, Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    iter,
    ops::{MulAssign, Neg},
    vec::Vec,
};
use merlin::Transcript;

use crate::errors::ProofError;
use crate::transcript::TranscriptProtocol;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct InnerProductProof<G: AffineRepr> {
    pub(crate) L_vec: Vec<G>,
    pub(crate) R_vec: Vec<G>,
    pub(crate) a: G::ScalarField,
    pub(crate) b: G::ScalarField,
}

impl<G: AffineRepr> InnerProductProof<G> {
    /// Create an inner-product proof.
    ///
    /// The proof is created with respect to the bases \\(G\\), \\(H'\\),
    /// where \\(H'\_i = H\_i \cdot \texttt{Hprime\\_factors}\_i\\).
    ///
    /// The `verifier` is passed in as a parameter so that the
    /// challenges depend on the *entire* transcript (including parent
    /// protocols).
    ///
    /// The lengths of the vectors must all be the same, and must all be
    /// either 0 or a power of 2.
    pub fn create(
        transcript: &mut Transcript,
        Q: &G,
        G_factors: &[G::ScalarField],
        H_factors: &[G::ScalarField],
        mut G_vec: Vec<G>,
        mut H_vec: Vec<G>,
        mut a_vec: Vec<G::ScalarField>,
        mut b_vec: Vec<G::ScalarField>,
    ) -> InnerProductProof<G> {
        // Create slices G, H, a, b backed by their respective
        // vectors.  This lets us reslice as we compress the lengths
        // of the vectors in the main loop below.
        let mut G = &mut G_vec[..];
        let mut H = &mut H_vec[..];
        let mut a = &mut a_vec[..];
        let mut b = &mut b_vec[..];

        let mut n = G.len();

        // All of the input vectors must have the same length.
        assert_eq!(G.len(), n);
        assert_eq!(H.len(), n);
        assert_eq!(a.len(), n);
        assert_eq!(b.len(), n);
        assert_eq!(G_factors.len(), n);
        assert_eq!(H_factors.len(), n);

        // All of the input vectors must have a length that is a power of two.
        assert!(n.is_power_of_two());

        <Transcript as TranscriptProtocol<G>>::innerproduct_domain_sep(transcript, n as u64);

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        // If it's the first iteration, unroll the Hprime = H*y_inv scalar mults
        // into multiscalar muls, for performance.
        if n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let bases = G_R
                .iter()
                .chain(H_L.iter())
                .chain(iter::once(Q))
                .map(|f| *f)
                .collect::<Vec<G>>();
            let scalars = a_L
                .iter()
                .zip(G_factors[n..2 * n].into_iter())
                .map(|(a_L_i, g)| *a_L_i * g)
                .chain(
                    b_R.iter()
                        .zip(H_factors[0..n].into_iter())
                        .map(|(b_R_i, h)| *b_R_i * h),
                )
                .chain(iter::once(c_L))
                .collect::<Vec<G::ScalarField>>();

            let L = G::Group::msm(&bases, &scalars).unwrap();

            let bases = G_L
                .iter()
                .chain(H_R.iter())
                .chain(iter::once(Q))
                .map(|f| *f)
                .collect::<Vec<G>>();
            let scalars = a_R
                .iter()
                .zip(G_factors[0..n].into_iter())
                .map(|(a_R_i, g)| *a_R_i * g)
                .chain(
                    b_L.iter()
                        .zip(H_factors[n..2 * n].into_iter())
                        .map(|(b_L_i, h)| *b_L_i * h),
                )
                .chain(iter::once(c_R))
                .collect::<Vec<G::ScalarField>>();

            let R = G::Group::msm(&bases, &scalars).unwrap();

            let L = L.into_affine();
            let R = R.into_affine();

            L_vec.push(L);
            R_vec.push(R);

            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);

            let u = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"u");

            let u_inv = u.inverse().unwrap();

            for i in 0..n {
                a_L[i] = a_L[i] * u + u_inv * a_R[i];
                b_L[i] = b_L[i] * u_inv + u * b_R[i];

                G_L[i] = G::Group::msm(
                    &[G_L[i], G_R[i]],
                    &[u_inv * G_factors[i], u * G_factors[n + i]],
                )
                .unwrap()
                .into_affine();

                H_L[i] = G::Group::msm(
                    &[H_L[i], H_R[i]],
                    &[u * H_factors[i], u_inv * H_factors[n + i]],
                )
                .unwrap()
                .into_affine();
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        while n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let bases = G_R
                .iter()
                .chain(H_L.iter())
                .chain(iter::once(Q))
                .map(|f| *f)
                .collect::<Vec<G>>();
            let scalars = a_L
                .iter()
                .chain(b_R.iter())
                .chain(iter::once(&c_L))
                .map(|f| *f)
                .collect::<Vec<G::ScalarField>>();

            let L = G::Group::msm(&bases, &scalars).unwrap();

            let bases = G_L
                .iter()
                .chain(H_R.iter())
                .chain(iter::once(Q))
                .map(|f| *f)
                .collect::<Vec<G>>();
            let scalars = a_R
                .iter()
                .chain(b_L.iter())
                .chain(iter::once(&c_R))
                .map(|f| *f)
                .collect::<Vec<G::ScalarField>>();

            let R = G::Group::msm(&bases, &scalars).unwrap();

            let L = L.into_affine();
            let R = R.into_affine();

            L_vec.push(L);
            R_vec.push(R);

            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);

            let u = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"u");
            let u_inv = u.inverse().unwrap();

            for i in 0..n {
                a_L[i] = a_L[i] * u + u_inv * a_R[i];
                b_L[i] = b_L[i] * u_inv + u * b_R[i];
                G_L[i] = G::Group::msm(&[G_L[i], G_R[i]], &[u_inv, u])
                    .unwrap()
                    .into_affine();
                H_L[i] = G::Group::msm(&[H_L[i], H_R[i]], &[u, u_inv])
                    .unwrap()
                    .into_affine()
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        InnerProductProof {
            L_vec,
            R_vec,
            a: a[0],
            b: b[0],
        }
    }

    /// Computes three vectors of verification scalars \\([u\_{i}^{2}]\\), \\([u\_{i}^{-2}]\\) and \\([s\_{i}]\\) for combined multiscalar multiplication
    /// in a parent protocol. See [inner product protocol notes](index.html#verification-equation) for details.
    /// The verifier must provide the input length \\(n\\) explicitly to avoid unbounded allocation within the inner product proof.
    pub(crate) fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<
        (
            Vec<G::ScalarField>,
            Vec<G::ScalarField>,
            Vec<G::ScalarField>,
        ),
        ProofError,
    > {
        let lg_n = self.L_vec.len();
        if lg_n >= 32 {
            // 4 billion multiplications should be enough for anyone
            // and this check prevents overflow in 1<<lg_n below.
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        <Transcript as TranscriptProtocol<G>>::innerproduct_domain_sep(transcript, n as u64);

        // 1. Recompute x_k,...,x_1 based on the proof transcript

        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            transcript.validate_and_append_point(b"L", L)?;
            transcript.validate_and_append_point(b"R", R)?;
            challenges.push(<Transcript as TranscriptProtocol<G>>::challenge_scalar(
                transcript, b"u",
            ));
        }

        // 2. Compute 1/(u_k...u_1) and 1/u_k, ..., 1/u_1

        let mut challenges_inv = challenges.clone();

        batch_inversion::<G::ScalarField>(&mut challenges_inv);

        let mut allinv = G::ScalarField::one();
        for f in challenges_inv.iter().filter(|f| !f.is_zero()) {
            allinv.mul_assign(f);
        }

        // 3. Compute u_i^2 and (1/u_i)^2

        for i in 0..lg_n {
            // XXX missing square fn upstream
            challenges[i] = challenges[i] * challenges[i];
            challenges_inv[i] = challenges_inv[i] * challenges_inv[i];
        }
        let challenges_sq = challenges;
        let challenges_inv_sq = challenges_inv;

        // 4. Compute s values inductively.

        let mut s = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [u_k,...,u_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
            s.push(s[i - k] * u_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }

    /// This method is for testing that proof generation work,
    /// but for efficiency the actual protocols would use `verification_scalars`
    /// method to combine inner product verification with other checks
    /// in a single multiscalar multiplication.
    #[allow(dead_code)]
    pub fn verify<IG, IH>(
        &self,
        n: usize,
        transcript: &mut Transcript,
        G_factors: IG,
        H_factors: IH,
        P: &G,
        Q: &G,
        G: &[G],
        H: &[G],
    ) -> Result<(), ProofError>
    where
        IG: IntoIterator,
        IG::Item: Borrow<G::ScalarField>,
        IH: IntoIterator,
        IH::Item: Borrow<G::ScalarField>,
    {
        let (u_sq, u_inv_sq, s) = self.verification_scalars(n, transcript)?;

        let g_times_a_times_s = G_factors
            .into_iter()
            .zip(s.iter())
            .map(|(g_i, s_i)| (self.a * s_i) * g_i.borrow())
            .take(G.len());

        // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
        let inv_s = s.iter().rev();

        let h_times_b_div_s = H_factors
            .into_iter()
            .zip(inv_s)
            .map(|(h_i, s_i_inv)| (self.b * s_i_inv) * h_i.borrow());

        let neg_u_sq = u_sq.iter().map(|ui| ui.neg());
        let neg_u_inv_sq = u_inv_sq.iter().map(|ui| ui.neg());

        let Ls = &self.L_vec;
        let Rs = &self.R_vec;

        let bases = iter::once(Q)
            .chain(G.iter())
            .chain(H.iter())
            .chain(Ls.iter())
            .chain(Rs.iter())
            .map(|f| f.clone())
            .collect::<Vec<G>>();

        let scalars = iter::once(self.a * self.b)
            .chain(g_times_a_times_s)
            .chain(h_times_b_div_s)
            .chain(neg_u_sq)
            .chain(neg_u_inv_sq)
            .collect::<Vec<G::ScalarField>>();

        let expect_P = G::Group::msm(&bases, &scalars).unwrap().into_affine();

        if expect_P == *P {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
    let mut out = F::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{io::Cursor, rand::SeedableRng, One, UniformRand};

    use crate::util;
    use digest::Digest;
    use rand_chacha::ChaChaRng;
    use sha3::Sha3_512;

    fn test_helper_create(n: usize) {
        type G = ark_secq256k1::Affine;

        let mut rng = rand::thread_rng();

        use crate::generators::BulletproofGens;
        let bp_gens = BulletproofGens::<G>::new(n, 1);
        let G_: Vec<G> = bp_gens.share(0).G(n).cloned().collect();
        let H: Vec<G> = bp_gens.share(0).H(n).cloned().collect();

        // Q would be determined upstream in the protocol, so we pick a random one.
        let Q = {
            let mut hash = Sha3_512::new();
            Digest::update(&mut hash, b"test point");
            let h = hash.finalize();

            let mut res = [0u8; 32];
            res.copy_from_slice(&h[..32]);

            let mut prng = ChaChaRng::from_seed(res);

            G::rand(&mut prng)
        };

        // a and b are the vectors for which we want to prove c = <a,b>
        let a: Vec<_> = (0..n)
            .map(|_| <G as AffineRepr>::ScalarField::rand(&mut rng))
            .collect();
        let b: Vec<_> = (0..n)
            .map(|_| <G as AffineRepr>::ScalarField::rand(&mut rng))
            .collect();
        let c = inner_product(&a, &b);

        let G_factors: Vec<<G as AffineRepr>::ScalarField> =
            iter::repeat(<G as AffineRepr>::ScalarField::one())
                .take(n)
                .collect();

        // y_inv is (the inverse of) a random challenge
        let y_inv = <G as AffineRepr>::ScalarField::rand(&mut rng);
        let H_factors: Vec<<G as AffineRepr>::ScalarField> =
            util::exp_iter::<G>(y_inv).take(n).collect();

        // P would be determined upstream, but we need a correct P to check the proof.
        //
        // To generate P = <a,G> + <b,H'> + <a,b> Q, compute
        //             P = <a,G> + <b',H> + <a,b> Q,
        // where b' = b \circ y^(-n)
        let b_prime = b
            .iter()
            .zip(util::exp_iter::<G>(y_inv))
            .map(|(bi, yi)| *bi * yi);
        // a.iter() has Item=&Fr, need Item=Fr to chain with b_prime
        let a_prime = a.iter().cloned();

        let bases = G_
            .iter()
            .chain(H.iter())
            .chain(iter::once(&Q))
            .map(|f| f.clone())
            .collect::<Vec<G>>();
        let scalars = a_prime
            .chain(b_prime)
            .chain(iter::once(c))
            .collect::<Vec<<G as AffineRepr>::ScalarField>>();

        let P = <G as AffineRepr>::Group::msm(&bases, &scalars)
            .unwrap()
            .into_affine();

        let mut verifier = Transcript::new(b"innerproducttest");
        let proof = InnerProductProof::create(
            &mut verifier,
            &Q,
            &G_factors,
            &H_factors,
            G_.clone(),
            H.clone(),
            a.clone(),
            b.clone(),
        );

        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat(<G as AffineRepr>::ScalarField::one()).take(n),
                util::exp_iter::<G>(y_inv).take(n),
                &P,
                &Q,
                &G_,
                &H
            )
            .is_ok());

        let bytes = {
            let mut cursor = Cursor::new(Vec::<u8>::new());
            proof.serialize_compressed(&mut cursor).unwrap();
            cursor.into_inner()
        };
        let mut cursor = Cursor::new(bytes);
        let proof = InnerProductProof::deserialize_compressed(&mut cursor).unwrap();

        let mut verifier = Transcript::new(b"innerproducttest");
        assert!(proof
            .verify(
                n,
                &mut verifier,
                iter::repeat(<G as AffineRepr>::ScalarField::one()).take(n),
                util::exp_iter::<G>(y_inv).take(n),
                &P,
                &Q,
                &G_,
                &H
            )
            .is_ok());
    }

    #[test]
    fn make_ipp_1() {
        test_helper_create(1);
    }

    #[test]
    fn make_ipp_2() {
        test_helper_create(2);
    }

    #[test]
    fn make_ipp_4() {
        test_helper_create(4);
    }

    #[test]
    fn make_ipp_32() {
        test_helper_create(32);
    }

    #[test]
    fn make_ipp_64() {
        test_helper_create(64);
    }

    #[test]
    fn test_inner_product() {
        type F = ark_secp256k1::Fr;

        let a = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
        let b = vec![F::from(2u64), F::from(3u64), F::from(4u64), F::from(5u64)];
        assert_eq!(F::from(40u64), inner_product(&a, &b));
    }
}
