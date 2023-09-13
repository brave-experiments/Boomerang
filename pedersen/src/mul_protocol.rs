//! Defines a protocol for proof of multiplication.
//! That is, let p be a prime and let x, y be two values in F_p.
//! This protocol proves that C_3 is a Pedersen commitment to z = x * y (over F_p)
//! The exact protocol we use here is the one given in https://eprint.iacr.org/2017/1132.pdf, Appendix A ("proving a product relationship").

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenComm, pedersen_config::PedersenConfig, transcript::MulTranscript,
    transcript::CHALLENGE_SIZE,
};

/// MulProof. This struct acts as a container for a MulProof.
/// Essentially, a new proof object can be created by calling `create`, whereas
/// an existing proof can be verified by calling `verify`.
/// Note that the documentation for this struct uses the notation that `z = x * y`.
/// Moreover, the challenge is `c` and the random values are `b1, ..., b5`.
/// We also have that X = xg + r_x h and Y = yg + r_y h.
pub struct MulProof<P: PedersenConfig> {
    /// alpha: a random point produced by the prover during setup.
    pub alpha: sw::Affine<P>,
    /// beta: a random point produced by the prover during setup.
    pub beta: sw::Affine<P>,
    /// delta: a random point produced by the prover during setup.
    pub delta: sw::Affine<P>,

    /// z1: the first part of the response. This is the same as b1 + c * x.
    pub z1: <P as CurveConfig>::ScalarField,
    /// z2: the second part of the response. This is the same as b2 + c * r_x.    
    pub z2: <P as CurveConfig>::ScalarField,
    /// z3: the third part of the response. This is the same as b3 + c * y.
    pub z3: <P as CurveConfig>::ScalarField,
    /// z4: the fourth part of the response. This is the same as b4 + c * r_y.    
    pub z4: <P as CurveConfig>::ScalarField,
    /// z4: the fifth part of the response. This is the same as b5 + c * (r_z - r_x * y).    
    pub z5: <P as CurveConfig>::ScalarField,
}

/// MulProofIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some way
/// before the proof is generated.
pub struct MulProofIntermediate<P: PedersenConfig> {
    /// alpha: a random point produced by the prover during setup.
    pub alpha: sw::Affine<P>,
    /// beta: a random point produced by the prover during setup.
    pub beta: sw::Affine<P>,
    /// delta: a random point produced by the prover during setup.
    pub delta: sw::Affine<P>,

    /// b1: a random private value made during setup.
    pub b1: <P as CurveConfig>::ScalarField,
    /// b2: a random private value made during setup.
    pub b2: <P as CurveConfig>::ScalarField,
    /// b3: a random private value made during setup.
    pub b3: <P as CurveConfig>::ScalarField,
    /// b4: a random private value made during setup.
    pub b4: <P as CurveConfig>::ScalarField,
    /// b5: a random private value made during setup.
    pub b5: <P as CurveConfig>::ScalarField,
}

impl<P: PedersenConfig> MulProof<P> {
    /// This is just to circumvent an annoying issue with Rust's current generics system.
    pub const CHAL_SIZE: usize = CHALLENGE_SIZE;

    /// add_to_transcript. This function simply adds self.alpha and the commitment `c1` to the `transcript`
    /// object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `c3` - the c3 commitment that is being added to the transcript.
    pub fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        Self::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta)
    }

    /// make_transcript. This function simply adds `c1`, `c2`, `c3` and `alpha_p` to the `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `c3` - the c3 commitment that is being added to the transcript.
    /// * `alpha_p` - the alpha value that is being added to the transcript.
    fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        alpha: &sw::Affine<P>,
        beta: &sw::Affine<P>,
        delta: &sw::Affine<P>,
    ) {
        // This function just builds the transcript out of the various input values.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C3", &compressed_bytes[..]);

        alpha.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);

        beta.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"beta", &compressed_bytes[..]);

        delta.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"delta", &compressed_bytes[..]);
    }

    /// create. This function returns a new multiplication proof of the fact that c3 is a commitment
    /// to x * y.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be cryptographically secure.
    /// * `x` - one of the multiplicands.
    /// * `y` - the other multiplicand.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z = x * y`.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self {
        Self::create_proof(
            x,
            y,
            &Self::create_intermediates(transcript, rng, c1, c2, c3),
            c1,
            c2,
            c3,
            &transcript.challenge_scalar(b"c")[..],
        )
    }

    /// create_intermediaries. This function returns a new set of intermediaries
    /// for a multiplication proof. Namely, this function proves that `c3` is a commitment for
    /// `z = x * y`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `c1` - the c1 commitment that is used. This is a commitment to `x`.
    /// * `c2` - the c2 commitment that is used. This is a commitment to `y`.
    /// * `c3` - the c3 commitment that is used. This is a commitment to `z = x * y`.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> MulProofIntermediate<P> {
        // Generate the random values.
        let b1 = <P as CurveConfig>::ScalarField::rand(rng);
        let b2 = <P as CurveConfig>::ScalarField::rand(rng);
        let b3 = <P as CurveConfig>::ScalarField::rand(rng);
        let b4 = <P as CurveConfig>::ScalarField::rand(rng);
        let b5 = <P as CurveConfig>::ScalarField::rand(rng);

        // This is Line 1 of Figure 5 of https://eprint.iacr.org/2017/1132.pdf.
        let alpha = (P::GENERATOR.mul(b1) + P::GENERATOR2.mul(b2)).into_affine();
        let beta = (P::GENERATOR.mul(b3) + P::GENERATOR2.mul(b4)).into_affine();
        let delta = (c1.comm.mul(b3) + P::GENERATOR2.mul(b5)).into_affine();

        // Add the values to the transcript.
        Self::make_transcript(
            transcript, &c1.comm, &c2.comm, &c3.comm, &alpha, &beta, &delta,
        );

        MulProofIntermediate {
            b1,
            b2,
            b3,
            b4,
            b5,
            alpha,
            beta,
            delta,
        }
    }

    /// create_proof. This function returns a new multiplication proof
    /// usign the previously collected intermediaries. Namely, this function proves that `c3` is a commitment for
    /// `z = x * y`.
    /// # Arguments
    /// * `x` - one of the multiplicands.
    /// * `y` - the other multiplicand.
    /// * `inter` - the intermediary values produced by a call to `create_intermediaries`.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z = x * y`.
    pub fn create_proof(
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        inter: &MulProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        // Make the challenge itself.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);

        Self {
            alpha: inter.alpha,
            beta: inter.beta,
            delta: inter.delta,
            z1: inter.b1 + (chal * (x)),
            z2: inter.b2 + (chal * c1.r),
            z3: inter.b3 + (chal * (y)),
            z4: inter.b4 + (chal * c2.r),
            z5: inter.b5 + chal * (c3.r - (c1.r * (y))),
        }
    }

    /// verify. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c3 is a valid
    /// commitment to a multiplied value and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z = x * y`.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool {
        Self::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta);
        self.verify_with_challenge(c1, c2, c3, &transcript.challenge_scalar(b"c")[..])
    }

    /// verify_with_challenge. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c3 is a valid
    /// commitment to a multiplied value and false otherwise. Notably, this function
    /// uses the pre-existing challenge bytes supplied in `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z = x * y`.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        chal_buf: &[u8],
    ) -> bool {
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        (self.alpha + c1.mul(chal) == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2))
            && (self.beta + c2.mul(chal) == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4))
            && (self.delta + c3.mul(chal) == c1.mul(self.z3) + P::GENERATOR2.mul(self.z5))
    }
}
