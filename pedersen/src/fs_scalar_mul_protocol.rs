//! Defines a protocol for EC scalar multiplication with Fiat-Shamir.
//! Essentially, this protocol is a repeated variant of Construction 4.1.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,
};

use merlin::Transcript;
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::{PedersenComm, PedersenConfig},
    scalar_mul::ScalarMulProtocol,
};

use std::marker::PhantomData;

/// FSECScalarMulProof. This struct acts as a container for the Fiat-Shamir scalar multiplication proof.
/// Essentially, this struct can be used to create new proofs (via ```create```), and verify existing proofs (via ```verify```).
pub struct FSECScalarMulProof<P: PedersenConfig, PT: ScalarMulProtocol<P>> {
    /// proofs: the sub-proofs.    
    proofs: Vec<PT>,
    _p: PhantomData<P>,
}

pub struct FSECScalarMulProofIntermediate<P: PedersenConfig, PT: ScalarMulProtocol<P>> {
    intermediates: Vec<PT::Intermediate>,
    _p: PhantomData<P>,
}

impl<P: PedersenConfig, PT: ScalarMulProtocol<P>> FSECScalarMulProof<P, PT> {
    /// create_intermediate. This function returns a set of intermediate values for
    /// s = λp for some publicly known point `P`. Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `s` - the secret, target point.
    /// * `rng` - the cryptographically secure RNG.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    #[allow(clippy::too_many_arguments)]
    pub fn create_intermediate<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> FSECScalarMulProofIntermediate<P, PT> {
        // Domain separate the transcript.
        PT::initialise_transcript(transcript);
        // Now initialise the initial proof objects.
        let mut intermediates = Vec::with_capacity(P::SECPARAM);
        for _ in 0..P::SECPARAM {
            intermediates.push(PT::create_intermediates_with_existing_commitments(
                transcript, rng, s, lambda, p, c1, r1, c2, c3,
            ));
        }

        FSECScalarMulProofIntermediate {
            intermediates,
            _p: PhantomData,
        }
    }

    /// create. This function creates a new scalar multiplication proof for s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `s` - the secret, target point.
    /// * `rng` - the cryptographically secure RNG.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    #[allow(clippy::too_many_arguments)]
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self {
        Self::create_proof(
            s,
            lambda,
            p,
            &Self::create_intermediate(transcript, rng, s, lambda, p, c1, r1, c2, c3),
            c1,
            r1,
            c2,
            c3,
            &PT::challenge_scalar(transcript)[0..(PT::SHIFT_BY * P::SECPARAM / 8)],
        )
    }

    /// create_proof_own_challenge.
    /// This function creates a new scalar multiplication proof for s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the associated T Curve.
    /// Moreover, this function generates its own challenges from the `transcript`.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `s` - the secret, target point.
    /// * `rng` - the cryptographically secure RNG.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `inter` - the pre-generated intermediate values.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proof_own_challenge(
        transcript: &mut Transcript,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &FSECScalarMulProofIntermediate<P, PT>,
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self {
        Self::create_proof(
            s,
            lambda,
            p,
            inter,
            c1,
            r1,
            c2,
            c3,
            &PT::challenge_scalar(transcript)[0..(PT::SHIFT_BY * P::SECPARAM / 8)],
        )
    }

    /// create_proof. This function creates a new scalar multiplication proof for s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the associated T Curve. The function also uses
    /// the challenge in `chal_buf`.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `s` - the secret, target point.
    /// * `rng` - the cryptographically secure RNG.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proof(
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &FSECScalarMulProofIntermediate<P, PT>,
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        let mut proofs = Vec::with_capacity(P::SECPARAM);
        for (i, c) in chal_buf.iter().enumerate() {
            let mut byte = *c;
            for j in 0..PT::SUB_ITER {
                proofs.push(PT::create_proof_with_challenge_byte(
                    s,
                    lambda,
                    p,
                    &inter.intermediates[(i * (8 / PT::SHIFT_BY)) + j],
                    byte,
                    c1,
                    r1,
                    c2,
                    c3,
                ));

                byte >>= PT::SHIFT_BY;
            }
        }

        Self {
            proofs,
            _p: PhantomData,
        }
    }

    /// add_to_transcript. This function adds all of the proof information held by `self`
    /// to the `transcript`. This includes all sub-proof objects.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.    
    pub fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        // Domain separate the transcript.
        PT::initialise_transcript(transcript);
        for proof in &self.proofs {
            proof.add_proof_to_transcript(transcript, c1, c2, c3);
        }
    }

    /// verify. This function verifies that the proof held by `self` is valid.
    /// Namely, this function checks that each individual sub-proof is correct and returns true
    /// if all proofs pass and false otherwise. This is equivalent to checking if s = λp for some publicly known point `P`
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `p` - the publicly known generator.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool {
        // Rebuild the transcript.
        self.add_to_transcript(transcript, c1, c2, c3);
        // Now just return the verification
        self.verify_proof(transcript, p, c1, c2, c3)
    }

    /// verify_proof. This function verifies that the proof held by `self` is valid.
    /// Namely, this function checks that each individual sub-proof is correct and returns true
    /// if all proofs pass and false otherwise. This is equivalent to checking if s = λp for some publicly known point `P`
    /// Note that this function differs from `verify` in that it assumes the transcript has already been built.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `p` - the publicly known generator.
    pub fn verify_proof(
        &self,
        transcript: &mut Transcript,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool {
        self.verify_proof_with_challenge(
            p,
            c1,
            c2,
            c3,
            &PT::challenge_scalar(transcript)[0..(PT::SHIFT_BY * P::SECPARAM / 8)],
        )
    }

    pub fn verify_proof_with_challenge(
        &self,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        chal_buf: &[u8],
    ) -> bool {
        // And now just check they all go through.
        let mut worked: bool = true;

        for (i, c) in chal_buf.iter().enumerate() {
            // Take the current challenge byte.
            let mut byte = *c;

            for j in 0..PT::SUB_ITER {
                worked &= self.proofs[i * (8 / PT::SHIFT_BY) + j]
                    .verify_with_challenge_byte(p, byte, c1, c2, c3);
                byte >>= PT::SHIFT_BY;
            }
        }

        worked
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        // N.B we write this in this way because ZKAttest proof sizes may vary.
        self.proofs.iter().map(|p| p.serialized_size()).sum()
    }
}
