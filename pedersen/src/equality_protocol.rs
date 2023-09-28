//! Defines an Equality protocol for various PedersenConfig types.
//! Specifically, this protocol shows in ZK that C1 and C2 are commitments to the
//! same underlying value (i.e C1 = Comm(x, r1), C2 = Comm(x, r2)).
//! This exact protocol comes from https://eprint.iacr.org/2017/1132.pdf, Appendix A (the "Commitment to the same value")
//! which is folklore.

use ark_ec::{
    short_weierstrass::{self as sw},
    AffineRepr, CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenComm, pedersen_config::PedersenConfig, transcript::EqualityTranscript,
};

/// EqualityProof. This struct acts as a container for an EqualityProof.
/// New proof objects can be made via the `create` function, whereas existing
/// proofs may be verified via the `verify` function.
pub struct EqualityProof<P: PedersenConfig> {
    /// alpha: the random point produced during setup.
    pub alpha: sw::Affine<P>,
    /// z: the response to the challenge (i.e z = chal * (c1.r - c2.r) + r.)
    pub z: <P as CurveConfig>::ScalarField,
}

/// EqualityProofIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some way
/// before the proof is generated.
pub struct EqualityProofIntermediate<P: PedersenConfig> {
    /// r: the random value produced by the prover.
    pub r: <P as CurveConfig>::ScalarField,
    /// alpha: the random point produced during setup.
    pub alpha: sw::Affine<P>,
}

/// EqualityProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `EqualityProofIntermediate` except from
/// the randomness values.
pub struct EqualityProofIntermediateTranscript<P: PedersenConfig> {
    /// alpha: the random point produced during setup.
    pub alpha: sw::Affine<P>,
}

/// EqualityProofTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can be, in some sense, added to the transcript for an equality proof.
pub trait EqualityProofTranscriptable {
    /// Affine: the type of random point.
    type Affine;
    /// add_to_transcript. This function simply adds the commitments `c1`, `c2` to the `transcript`
    /// object, along with the internal `alpha` value.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.    
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine, c2: &Self::Affine);
}

// We need to implement these for generic structs.
impl<P: PedersenConfig> Copy for EqualityProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for EqualityProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: PedersenConfig> EqualityProof<P> {
    /// make_intermediate_transcript. This function turns some of equality proof intermediates into
    /// a transcriptable object. This is typically only useful for proofs that only conditionally construct
    /// equality proofs.
    /// # Arguments
    /// * `inter` - the intermediates to be converted.
    pub fn make_intermediate_transcript(
        inter: EqualityProofIntermediate<P>,
    ) -> EqualityProofIntermediateTranscript<P> {
        EqualityProofIntermediateTranscript { alpha: inter.alpha }
    }

    /// make_transcript. This function simply adds `c1`, `c2` and `alpha_p` to the `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the c1 commitment that is being added to the transcript.
    /// * `c2` - the c2 commitment that is being added to the transcript.
    /// * `alpha_p` - the alpha value that is being added to the transcript.
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        alpha_p: &sw::Affine<P>,
    ) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C2", &compressed_bytes[..]);

        alpha_p.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);
    }

    /// create_intermediaries. This function returns a new set of intermediaries
    /// for an equality proof for `c1` against `c2`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `c1` - the c1 commitment that is used.
    /// * `c2` - the c2 commitment that is used.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
    ) -> EqualityProofIntermediate<P> {
        let r = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = P::GENERATOR2.mul(r).into_affine();
        Self::make_transcript(transcript, &c1.comm, &c2.comm, &alpha);
        EqualityProofIntermediate { r, alpha }
    }

    /// create. This function returns a new equality proof for `c1` against `c2`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be cryptographically secure.
    /// * `c1` - the c1 commitment that is used.
    /// * `c2` - the c2 commitment that is used.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
    ) -> Self {
        Self::create_proof(
            &Self::create_intermediates(transcript, rng, c1, c2),
            c1,
            c2,
            &transcript.challenge_scalar(b"c")[..],
        )
    }

    /// create_proof. This function accepts a set of intermediaries (`inter`) and proves
    /// that `c1` and `c2` are commitments to the same value.    
    /// # Arguments
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `c1` - the c1 commitment.
    /// * `c2` - the c2 commitment.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn create_proof(
        inter: &EqualityProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        Self::create_proof_with_challenge(
            inter,
            c1,
            c2,
            &<P as PedersenConfig>::make_challenge_from_buffer(chal_buf),
        )
    }

    /// create_proof_with_challenge. This function accepts a set of intermediaries (`inter`) and creates
    /// a proof that `c1` and `c2` are commitments to the same value. This function creates this proof using
    /// the challenge `chal`.
    /// # Arguments
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `c1` - the c1 commitment.
    /// * `c2` - the c2 commitment.
    /// * `chal` - the challenge to be used.    
    pub fn create_proof_with_challenge(
        inter: &EqualityProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let z = if *chal == P::CM1 {
            inter.r - (c1.r - c2.r)
        } else if *chal == P::CP1 {
            (c1.r - c2.r) + inter.r
        } else {
            *chal * (c1.r - c2.r) + inter.r
        };

        EqualityProof {
            alpha: inter.alpha,
            z,
        }
    }

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if c1 and c2 are commitments to the same secret value.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `c1` - the c1 commitment.
    /// * `c2` - the c2 commitment.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
    ) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, c1, c2);
        self.verify_proof(c1, c2, &transcript.challenge_scalar(b"c")[..])
    }

    /// verify_proof. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if c1 and c2 are commitments to the same secret value.
    /// Note that this function uses the pre-existing challenge bytes supplied in `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment.
    /// * `c2` - the c2 commitment.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn verify_proof(&self, c1: &sw::Affine<P>, c2: &sw::Affine<P>, chal_buf: &[u8]) -> bool {
        self.verify_with_challenge(
            c1,
            c2,
            &<P as PedersenConfig>::make_challenge_from_buffer(chal_buf),
        )
    }

    /// verify_with_challenge. This function returns true if the proof held by `self` is valid and false otherwise.
    /// In other words, this function returns true if c1 and c2 are commitments to the same secret value.
    /// Note that this function uses the pre-existing challenge bytes supplied in `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the c1 commitment.
    /// * `c2` - the c2 commitment.
    /// * `chal` - the buffer that contains the challenge.
    pub fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        let rhs = if *chal == P::CP1 {
            (c1.into_group() - c2).into_affine()
        } else if *chal == P::CM1 {
            (c2.into_group() - c1).into_affine()
        } else {
            ((c1.into_group() - c2).mul(*chal)).into_affine()
        };

        P::GENERATOR2.mul(self.z) - self.alpha == rhs
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.z.compressed_size() + self.alpha.compressed_size()
    }
}

impl<P: PedersenConfig> EqualityProofTranscriptable for EqualityProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine, c2: &Self::Affine) {
        EqualityProof::make_transcript(transcript, c1, c2, &self.alpha);
    }
}

impl<P: PedersenConfig> EqualityProofTranscriptable for EqualityProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine, c2: &Self::Affine) {
        EqualityProof::make_transcript(transcript, c1, c2, &self.alpha);
    }
}

impl<P: PedersenConfig> EqualityProofTranscriptable for EqualityProofIntermediateTranscript<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
    ) {
        EqualityProof::make_transcript(transcript, c1, c2, &self.alpha);
    }
}

impl<P: PedersenConfig> EqualityProofIntermediateTranscript<P> {
    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.alpha.compressed_size()
    }
}
