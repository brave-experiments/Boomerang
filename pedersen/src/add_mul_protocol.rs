//! Defines a protocol for proof of multiplication.
//! That is, let p be a prime and let x, y be two values in F_p.
//! This protocol proves that C_3 is a Pedersen commitment to z = x * y (over F_p)
//! The exact protocol we use here is the one given in https://eprint.iacr.org/2017/1132.pdf, Appendix A ("proving a product relationship").

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenComm, pedersen_config::PedersenConfig, transcript::AddMulTranscript,
};

/// AddMulProofTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can be, in some sense, added to the transcript for a multiplication proof.
pub trait AddMulProofTranscriptable {
    /// Affine: the type of random point.
    type Affine;
    /// add_to_transcript. This function simply adds  the commitment various commitments to the `transcript`
    /// object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `c3` - the c3 commitment that is being added to the transcript.
    /// * `c4` - the c3 commitment that is being added to the transcript.
    /// * `c5` - the c3 commitment that is being added to the transcript.
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &Self::Affine,
        c2: &Self::Affine,
        c3: &Self::Affine,
        c4: &Self::Affine,
        c5: &Self::Affine,
    );
}

/// AddMulProof. This struct acts as a container for an AddMulProof.
/// Essentially, a new proof object can be created by calling `create`, whereas
/// an existing proof can be verified by calling `verify`.
/// Note that the documentation for this struct uses the notation that `t = (x * y) + z`.
/// Moreover, the challenge is `c` and the random values are `b1, ..., b9`.
/// We also have that X = xg + r_x h and Y = yg + r_y h.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AddMulProof<P: PedersenConfig> {
    /// t1: a random point produced by the prover during setup.
    pub t1: sw::Affine<P>,
    /// t2: a random point produced by the prover during setup.
    pub t2: sw::Affine<P>,
    /// t3: a random point produced by the prover during setup.
    pub t3: sw::Affine<P>,
    /// t4: a random point produced by the prover during setup.
    pub t4: sw::Affine<P>,
    /// t5: a random point produced by the prover during setup.
    pub t5: sw::Affine<P>,
    /// t6: a random point produced by the prover during setup.
    pub t6: sw::Affine<P>,

    /// z1: the first part of the response. This is the same as b1 + c * x.
    pub z1: <P as CurveConfig>::ScalarField,
    /// z2: the second part of the response. This is the same as b2 + c * r_x.
    pub z2: <P as CurveConfig>::ScalarField,
    /// z3: the third part of the response. This is the same as b3 + c * y.
    pub z3: <P as CurveConfig>::ScalarField,
    /// z4: the fourth part of the response. This is the same as b4 + c * r_y.
    pub z4: <P as CurveConfig>::ScalarField,
    /// z5: the fifth part of the response. This is the same as b5 + c * (r_z - r_x * y).
    pub z5: <P as CurveConfig>::ScalarField,
    /// z6: the fifth part of the response. This is the same as b5 + c * (r_z - r_x * y).
    pub z6: <P as CurveConfig>::ScalarField,
    /// z7: the fifth part of the response. This is the same as b5 + c * (r_z - r_x * y).
    pub z7: <P as CurveConfig>::ScalarField,
    /// z8: the fifth part of the response. This is the same as b5 + c * (r_z - r_x * y).
    pub z8: <P as CurveConfig>::ScalarField,
    /// z9: the fifth part of the response. This is the same as b5 + c * (r_z - r_x * y).
    pub z9: <P as CurveConfig>::ScalarField,
}

/// AddMulProofIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some way
/// before the proof is generated.
pub struct AddMulProofIntermediate<P: PedersenConfig> {
    /// t1: a random point produced by the prover during setup.
    pub t1: sw::Affine<P>,
    /// t2: a random point produced by the prover during setup.
    pub t2: sw::Affine<P>,
    /// t3: a random point produced by the prover during setup.
    pub t3: sw::Affine<P>,
    /// t4: a random point produced by the prover during setup.
    pub t4: sw::Affine<P>,
    /// t5: a random point produced by the prover during setup.
    pub t5: sw::Affine<P>,
    /// t6: a random point produced by the prover during setup.
    pub t6: sw::Affine<P>,

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
    /// b6: a random private value made during setup.
    pub b6: <P as CurveConfig>::ScalarField,
    /// b7: a random private value made during setup.
    pub b7: <P as CurveConfig>::ScalarField,
    /// b8: a random private value made during setup.
    pub b8: <P as CurveConfig>::ScalarField,
    /// b9: a random private value made during setup.
    pub b9: <P as CurveConfig>::ScalarField,
}

// We need to implement these manually for generic structs.
impl<P: PedersenConfig> Copy for AddMulProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for AddMulProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
}

/// AddMulProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `AddMulProofIntermediate` except from
/// the randomness values.
pub struct AddMulProofIntermediateTranscript<P: PedersenConfig> {
    /// t1: a random point produced by the prover during setup.
    pub t1: sw::Affine<P>,
    /// t2: a random point produced by the prover during setup.
    pub t2: sw::Affine<P>,
    /// t3: a random point produced by the prover during setup.
    pub t3: sw::Affine<P>,
    /// t4: a random point produced by the prover during setup.
    pub t4: sw::Affine<P>,
    /// t5: a random point produced by the prover during setup.
    pub t5: sw::Affine<P>,
    /// t6: a random point produced by the prover during setup.
    pub t6: sw::Affine<P>,
}

impl<P: PedersenConfig> AddMulProof<P> {
    /// make_intermediate_transcript. This function accepts a set of intermediate values (`inter`)
    /// and builds a new AddMulProofIntermediateTranscript from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn make_intermediate_transcript(
        inter: AddMulProofIntermediate<P>,
    ) -> AddMulProofIntermediateTranscript<P> {
        AddMulProofIntermediateTranscript {
            t1: inter.t1,
            t2: inter.t2,
            t3: inter.t3,
            t4: inter.t4,
            t5: inter.t5,
            t6: inter.t6,
        }
    }

    /// make_transcript. This function simply adds `c1`, `c2`, `c3`, `c4`, `c5`, and `alpha_p` to the `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `c3` - the c3 commitment that is being added to the transcript.
    /// * `c4` - the c3 commitment that is being added to the transcript.
    /// * `c5` - the c3 commitment that is being added to the transcript.
    /// * `alpha` - the alpha value that is being added to the transcript.
    /// * `beta` - the beta value that is being added to the transcript.
    /// * `delta` - the delta value that is being added to the transcript.
    #[allow(clippy::too_many_arguments)]
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        t1: &sw::Affine<P>,
        t2: &sw::Affine<P>,
        t3: &sw::Affine<P>,
        t4: &sw::Affine<P>,
        t5: &sw::Affine<P>,
        t6: &sw::Affine<P>,
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

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C5", &compressed_bytes[..]);

        t1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"t1", &compressed_bytes[..]);

        t2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"t2", &compressed_bytes[..]);

        t3.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"t3", &compressed_bytes[..]);

        t4.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"t4", &compressed_bytes[..]);

        t5.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"t5", &compressed_bytes[..]);

        t6.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"t6", &compressed_bytes[..]);
    }

    /// create. This function returns a new multiplication proof of the fact that c5 is a commitment
    /// to (x * y) + z.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be cryptographically secure.
    /// * `x` - one of the values.
    /// * `y` - the other value.
    /// * `z` - the other value.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z = x * y`.
    /// * `c4` - the commitment to `w = x * y`.
    /// * `c5` - the commitment to `t = w + z`.
    #[allow(clippy::too_many_arguments)]
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        z: &<P as CurveConfig>::ScalarField,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
    ) -> Self {
        Self::create_proof(
            x,
            y,
            z,
            &Self::create_intermediates(transcript, rng, c1, c2, c3, c4, c5),
            c1,
            c2,
            c3,
            c4,
            c5,
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
    /// * `c3` - the c3 commitment that is used. This is a commitment to `z`.
    /// * `c4` - the c3 commitment that is used. This is a commitment to `w = x * y`.
    /// * `c5` - the c3 commitment that is used. This is a commitment to `t = w + z`.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
    ) -> AddMulProofIntermediate<P> {
        // Generate the random values.
        let b1 = <P as CurveConfig>::ScalarField::rand(rng);
        let b2 = <P as CurveConfig>::ScalarField::rand(rng);
        let b3 = <P as CurveConfig>::ScalarField::rand(rng);
        let b4 = <P as CurveConfig>::ScalarField::rand(rng);
        let b5 = <P as CurveConfig>::ScalarField::rand(rng);
        let b6 = <P as CurveConfig>::ScalarField::rand(rng);
        let b7 = <P as CurveConfig>::ScalarField::rand(rng);
        let b8 = <P as CurveConfig>::ScalarField::rand(rng);
        let b9 = <P as CurveConfig>::ScalarField::rand(rng);

        let t1 = (P::GENERATOR.mul(b1) + P::GENERATOR2.mul(b2)).into_affine();
        let t2 = (P::GENERATOR.mul(b3) + P::GENERATOR2.mul(b4)).into_affine();
        let t3 = (P::GENERATOR.mul(b5) + P::GENERATOR2.mul(b6)).into_affine();
        let t4 = (c1.comm.mul(b3) + P::GENERATOR2.mul(b7)).into_affine();
        let t5 = (P::GENERATOR.mul(b8)).into_affine();
        let t6 = (P::GENERATOR2.mul(b9)).into_affine();

        // Add the values to the transcript.
        Self::make_transcript(
            transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &t1, &t2, &t3, &t4, &t5,
            &t6,
        );

        AddMulProofIntermediate {
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7,
            b8,
            b9,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    /// create_proof. This function returns a new add-multiplication proof
    /// usign the previously collected intermediates. Namely, this function proves that `c5` is a commitment for
    /// `t = (x * y) + z`. Note that this function builds the challenge from the bytes supplied in `chal_buf`.
    ///
    /// # Arguments
    /// * `x` - one of the values.
    /// * `y` - the other value.
    /// * `z` - the other value.
    /// * `inter` - the intermediary values produced by a call to `create_intermediates`.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z`.
    /// * `c4` - the c3 commitment that is used. This is a commitment to `w = x * y`.
    /// * `c5` - the c3 commitment that is used. This is a commitment to `t = w + z`.
    /// * `chal_buf` - the pre-determined challenge bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proof(
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        z: &<P as CurveConfig>::ScalarField,
        inter: &AddMulProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        // Make the challenge itself.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        Self::create_proof_with_challenge(x, y, z, inter, c1, c2, c3, c4, c5, &chal)
    }

    /// create_proof_with_challenge. This function creates a proof of multiplication
    /// using the pre-existing challenge `chal`. This function should only be used when the
    /// challenge is fixed across multiple, separate proofs.
    ///
    /// # Arguments
    /// * `x` - one of the values.
    /// * `y` - the other value.
    /// * `z` - the other value.
    /// * `inter` - the intermediary values produced by a call to `create_intermediates`.
    /// * `c1` - the commitment to `x`.
    /// * `c2` - the commitment to `y`.
    /// * `c3` - the commitment to `z`.
    /// * `c4` - the c3 commitment that is used. This is a commitment to `w = x * y`.
    /// * `c5` - the c3 commitment that is used. This is a commitment to `t = w + z`.
    /// * `chal` - the challenge.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proof_with_challenge(
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        z: &<P as CurveConfig>::ScalarField,
        inter: &AddMulProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let z1 = inter.b1 + (*chal * (x));
        let z2 = inter.b2 + (*chal * c1.r);
        let z3 = inter.b3 + (*chal * y);
        let z4 = inter.b4 + (*chal * c2.r);
        let z5 = inter.b5 + (*chal * z);
        let z6 = inter.b6 + (*chal * c3.r);
        let z7 = inter.b7 + *chal * (c4.r - (c1.r * (y)));
        let z8 = inter.b8 + *chal * ((*x * y) + z);
        let z9 = inter.b9 + *chal * (c5.r);

        Self {
            t1: inter.t1,
            t2: inter.t2,
            t3: inter.t3,
            t4: inter.t4,
            t5: inter.t5,
            t6: inter.t6,
            z1,
            z2,
            z3,
            z4,
            z5,
            z6,
            z7,
            z8,
            z9,
        }
    }

    /// verify. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c5 is a valid
    /// commitment and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z`.
    /// * `c4` - the c3 commitment. This acts as a commitment to `w = x * y`.
    /// * `c5` - the c3 commitment. This acts as a commitment to `t = w + z`.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
    ) -> bool {
        Self::make_transcript(
            transcript, c1, c2, c3, c4, c5, &self.t1, &self.t2, &self.t3, &self.t4, &self.t5,
            &self.t6,
        );
        self.verify_proof(c1, c2, c3, c4, c5, &transcript.challenge_scalar(b"c")[..])
    }

    /// verify_proof. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c5 is a valid
    /// commitment and false otherwise. Notably, this function
    /// uses the pre-existing challenge bytes supplied in `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z`.
    /// * `c4` - the c3 commitment. This acts as a commitment to `w = x * y`.
    /// * `c5` - the c3 commitment. This acts as a commitment to `t = w + z`.
    pub fn verify_proof(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        chal_buf: &[u8],
    ) -> bool {
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        self.verify_with_challenge(c1, c2, c3, c4, c5, &chal)
    }

    /// verify_with_challenge. This function simply verifies that the proof held by `self` is a valid
    /// multiplication proof. Put differently, this function returns true if c3 is a valid
    /// commitment to a multiplied value and false otherwise. Notably, this function
    /// uses the pre-existing challenge supplied in `chal`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment. This acts as a commitment to `x`.
    /// * `c2` - the c2 commitment. This acts as a commitment to `y`.
    /// * `c3` - the c3 commitment. This acts as a commitment to `z`.
    /// * `c4` - the c3 commitment. This acts as a commitment to `w = x * y`.
    /// * `c5` - the c3 commitment. This acts as a commitment to `t = w + z`.
    /// * `chal` - the challenge.
    pub fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        (self.t1 + c1.mul(*chal) == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2))
            && (self.t2 + c2.mul(*chal) == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4))
            && (self.t3 + c3.mul(*chal) == P::GENERATOR.mul(self.z5) + P::GENERATOR2.mul(self.z6))
            && (self.t4 + c4.mul(*chal) == c1.mul(self.z3) + P::GENERATOR2.mul(self.z7))
            && ((self.t6 + self.t5) + c5.mul(*chal)
                == P::GENERATOR.mul(self.z8) + P::GENERATOR2.mul(self.z9))
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.t1.compressed_size()
            + self.t2.compressed_size()
            + self.t3.compressed_size()
            + self.t4.compressed_size()
            + self.t5.compressed_size()
            + self.t6.compressed_size()
            + self.z1.compressed_size()
            + self.z2.compressed_size()
            + self.z3.compressed_size()
            + self.z4.compressed_size()
            + self.z5.compressed_size()
            + self.z6.compressed_size()
            + self.z7.compressed_size()
            + self.z8.compressed_size()
            + self.z9.compressed_size()
    }
}

impl<P: PedersenConfig> AddMulProofTranscriptable for AddMulProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &Self::Affine,
        c2: &Self::Affine,
        c3: &Self::Affine,
        c4: &Self::Affine,
        c5: &Self::Affine,
    ) {
        AddMulProof::make_transcript(
            transcript, c1, c2, c3, c4, c5, &self.t1, &self.t2, &self.t3, &self.t4, &self.t5,
            &self.t6,
        );
    }
}

impl<P: PedersenConfig> AddMulProofTranscriptable for AddMulProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
    ) {
        AddMulProof::make_transcript(
            transcript, c1, c2, c3, c4, c5, &self.t1, &self.t2, &self.t3, &self.t4, &self.t5,
            &self.t6,
        );
    }
}

impl<P: PedersenConfig> AddMulProofTranscriptable for AddMulProofIntermediateTranscript<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
    ) {
        AddMulProof::make_transcript(
            transcript, c1, c2, c3, c4, c5, &self.t1, &self.t2, &self.t3, &self.t4, &self.t5,
            &self.t6,
        );
    }
}

impl<P: PedersenConfig> AddMulProofIntermediateTranscript<P> {
    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.t1.compressed_size()
            + self.t2.compressed_size()
            + self.t3.compressed_size()
            + self.t4.compressed_size()
            + self.t5.compressed_size()
            + self.t6.compressed_size()
    }
}
