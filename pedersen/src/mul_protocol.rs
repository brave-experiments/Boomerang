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
};

/// MulProofTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can be, in some sense, added to the transcript for a multiplication proof.
pub trait MulProofTranscriptable {
    /// Affine: the type of random point.
    type Affine;
    /// add_to_transcript. This function simply adds  the commitment various commitments to the `transcript`
    /// object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `c3` - the c3 commitment that is being added to the transcript.
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &Self::Affine,
        c2: &Self::Affine,
        c3: &Self::Affine,
    );
}

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

// We need to implement these manually for generic structs.
impl<P: PedersenConfig> Copy for MulProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for MulProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
}

/// MulProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `MulProofIntermediate` except from
/// the randomness values.
pub struct MulProofIntermediateTranscript<P: PedersenConfig> {
    /// alpha: a random point produced by the prover during setup.
    pub alpha: sw::Affine<P>,
    /// beta: a random point produced by the prover during setup.
    pub beta: sw::Affine<P>,
    /// delta: a random point produced by the prover during setup.
    pub delta: sw::Affine<P>,
}

impl<P: PedersenConfig> MulProof<P> {
    /// make_intermediate_transcript. This function accepts a set of intermediate values (`inter`)
    /// and builds a new MulProofIntermediateTranscript from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn make_intermediate_transcript(
        inter: MulProofIntermediate<P>,
    ) -> MulProofIntermediateTranscript<P> {
        MulProofIntermediateTranscript {
            alpha: inter.alpha,
            beta: inter.beta,
            delta: inter.delta,
        }
    }

    /// make_transcript. This function simply adds `c1`, `c2`, `c3` and `alpha_p` to the `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `c3` - the c3 commitment that is being added to the transcript.
    /// * `alpha` - the alpha value that is being added to the transcript.
    /// * `beta` - the beta value that is being added to the transcript.
    /// * `delta` - the delta value that is being added to the transcript.
    pub fn make_transcript(
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

    /// create_intermediates. This function returns a new set of intermediates
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
    /// usign the previously collected intermediates. Namely, this function proves that `c3` is a commitment for
    /// `z = x * y`. Note that this function builds the challenge from the bytes supplied in `chal_buf`.
    ///
    /// # Arguments
    /// * `x` - one of the multiplicands.
    /// * `y` - the other multiplicand.
    /// * `inter` - the intermediary values produced by a call to `create_intermediates`.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z = x * y`.
    /// * `chal_buf` - the pre-determined challenge bytes.
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
        Self::create_proof_with_challenge(x, y, inter, c1, c2, c3, &chal)
    }

    /// create_proof_with_challenge. This function creates a proof of multiplication
    /// using the pre-existing challenge `chal`. This function should only be used when the
    /// challenge is fixed across multiple, separate proofs.
    ///
    /// # Arguments
    /// * `x` - one of the multiplicands.
    /// * `y` - the other multiplicand.
    /// * `inter` - the intermediary values produced by a call to `create_intermediates`.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z = x * y`.
    /// * `chal` - the challenge.
    pub fn create_proof_with_challenge(
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        inter: &MulProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let (z1, z2, z3, z4, z5) = if *chal == P::CM1 {
            (
                inter.b1 - x,
                inter.b2 - c1.r,
                inter.b3 - y,
                inter.b4 - c2.r,
                inter.b5 - (c3.r - (c1.r * y)),
            )
        } else if *chal == P::CP1 {
            (
                inter.b1 + x,
                inter.b2 + c1.r,
                inter.b3 + y,
                inter.b4 + c2.r,
                inter.b5 + (c3.r - (c1.r * y)),
            )
        } else {
            (
                inter.b1 + (*chal * (x)),
                inter.b2 + (*chal * c1.r),
                inter.b3 + (*chal * y),
                inter.b4 + (*chal * c2.r),
                inter.b5 + *chal * (c3.r - (c1.r * (y))),
            )
        };

        Self {
            alpha: inter.alpha,
            beta: inter.beta,
            delta: inter.delta,
            z1,
            z2,
            z3,
            z4,
            z5,
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
        self.verify_proof(c1, c2, c3, &transcript.challenge_scalar(b"c")[..])
    }

    /// verify_proof. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c3 is a valid
    /// commitment to a multiplied value and false otherwise. Notably, this function
    /// uses the pre-existing challenge bytes supplied in `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z = x * y`.
    pub fn verify_proof(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        chal_buf: &[u8],
    ) -> bool {
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        self.verify_with_challenge(c1, c2, c3, &chal)
    }

    /// verify_with_challenge. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c3 is a valid
    /// commitment to a multiplied value and false otherwise. Notably, this function
    /// uses the pre-existing challenge supplied in `chal`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z = x * y`.
    /// * `chal` - the challenge.
    pub fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        if *chal == P::CM1 {
            (self.alpha - c1 == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2))
                && (self.beta - c2 == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4))
                && (self.delta - c3 == c1.mul(self.z3) + P::GENERATOR2.mul(self.z5))
        } else if *chal == P::CP1 {
            (self.alpha + c1 == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2))
                && (self.beta + c2 == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4))
                && (self.delta + c3 == c1.mul(self.z3) + P::GENERATOR2.mul(self.z5))
        } else {
            (self.alpha + c1.mul(*chal) == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2))
                && (self.beta + c2.mul(*chal)
                    == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4))
                && (self.delta + c3.mul(*chal) == c1.mul(self.z3) + P::GENERATOR2.mul(self.z5))
        }
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.alpha.compressed_size()
            + self.beta.compressed_size()
            + self.delta.compressed_size()
            + self.z1.compressed_size()
            + self.z2.compressed_size()
            + self.z3.compressed_size()
            + self.z4.compressed_size()
            + self.z5.compressed_size()
    }
}

impl<P: PedersenConfig> MulProofTranscriptable for MulProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &Self::Affine,
        c2: &Self::Affine,
        c3: &Self::Affine,
    ) {
        MulProof::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta);
    }
}

impl<P: PedersenConfig> MulProofTranscriptable for MulProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        MulProof::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta);
    }
}

impl<P: PedersenConfig> MulProofTranscriptable for MulProofIntermediateTranscript<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        MulProof::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta);
    }
}

impl<P: PedersenConfig> MulProofIntermediateTranscript<P> {
    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.alpha.compressed_size() + self.beta.compressed_size() + self.delta.compressed_size()
    }
}
