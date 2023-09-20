//! Defines a protocol for proving a commitment to 0 or 1 for various PedersenConfig types.
//! Specifically, this protocol shows in ZK that a particular commitment is a commitment to either 0 or 1.
//! This protocol uses the same language as https://eprint.iacr.org/2014/764.pdf, Figure 1, but the protocol
//! likely predates that work.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,    
};
use merlin::Transcript;

use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use std::ops::Mul;
use ark_ff::Field;
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::{PedersenComm, PedersenConfig}, transcript::GKZeroOneTranscript,
};

/// ZeroOneProofTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can, in some sense, be added to a transcript for the zero-one proof.
pub trait ZeroOneProofTranscriptable {
    /// Affine: the type of random point.
    type Affine;

    /// add_to_transcript. This function simply adds the commitments held by `self` to the `transcript`
    /// object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript which is modified.
    fn add_to_transcript(&self, transcript: &mut Transcript);
}

/// ZeroOneProof. This struct acts as a container for a zero-one proof.
/// New proof objects can be made via the `create` function, whereas existing
/// proofs may be verified via the `verify` function.
pub struct ZeroOneProof<P: PedersenConfig> {
    /// ca: the commitment to the random value `a`.
    pub ca: sw::Affine<P>,

    /// cb: the commitment to `am`.
    pub cb: sw::Affine<P>,
        
    /// f: the mx + a value.
    pub f: <P as CurveConfig>::ScalarField,
    /// z_a: the rx + s value.
    pub z_a: <P as CurveConfig>::ScalarField,

    /// z_b: the r*(x-f) + t value.
    pub z_b: <P as CurveConfig>::ScalarField,
}

/// ZeroOneProofIntermediate. This struct provides a convenient wrapper for building
/// all of the the random values _before_ the challenge is generated. This struct
/// should only be used if the transcript needs to be modified in some way before
/// the proof is generated.
pub struct ZeroOneProofIntermediate<P: PedersenConfig> {
    /// ca: the commitment to the random value `a`.
    pub ca: PedersenComm<P>,

    /// cb: the commitment to `am`.
    pub cb: PedersenComm<P>,
        
    /// a: a random value
    pub a: <P as CurveConfig>::ScalarField,

    /// s: a random value.
    pub s: <P as CurveConfig>::ScalarField,

    /// s: a random value.
    pub t: <P as CurveConfig>::ScalarField,
}

/// ZeroOneProofIntermediateTranscript. This struct provides a wrapper for 
/// every input into the transcript i.e everything that's in `ZeroOneProofIntermediate` except
/// for the random values.
pub struct ZeroOneProofIntermediateTranscript<P: PedersenConfig> {
    /// ca: the commitment to the random value `a`.
    pub ca: sw::Affine<P>,

    /// cb: the commitment to `am`.
    pub cb: sw::Affine<P>,     
}

impl<P: PedersenConfig> ZeroOneProof<P> {

    pub fn make_intermediate_transcript(inter: ZeroOneProofIntermediate<P>) -> ZeroOneProofIntermediateTranscript<P> {
        ZeroOneProofIntermediateTranscript { ca: inter.ca.comm, cb: inter.cb.comm } 
    }

    pub fn make_transcript(transcript: &mut Transcript, ca: &sw::Affine<P>, cb: &sw::Affine<P>) {
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        ca.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"ca", &compressed_bytes[..]);

        cb.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"cb", &compressed_bytes[..]);
    }
    
    pub fn create_intermediates<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                                        rng: &mut T,
                                                        m: &<P as CurveConfig>::ScalarField) -> ZeroOneProofIntermediate<P> {
        
        let a = <P as CurveConfig>::ScalarField::rand(rng);
        let s = <P as CurveConfig>::ScalarField::rand(rng);
        let t = <P as CurveConfig>::ScalarField::rand(rng);

        let ca = PedersenComm::new_with_both(a, s);
        let cb = PedersenComm::new_with_both(a * m, t);
        Self::make_transcript(transcript, &ca.comm, &cb.comm);
        ZeroOneProofIntermediate { ca, cb, a, s, t}        
    }

    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        m: &<P as CurveConfig>::ScalarField,
        c: &PedersenComm<P>) -> Self {

        Self::create_proof(&Self::create_intermediates(transcript, rng, m),
                           m,
                           c,
                           &transcript.challenge_scalar(b"c")[..],)
    }

    pub fn create_proof(inter: &ZeroOneProofIntermediate<P>,
                        m: &<P as CurveConfig>::ScalarField,
                        c: &PedersenComm<P>,
                        chal_buf: &[u8]) -> Self {
        Self::create_proof_with_challenge(inter, m, c, &<P as PedersenConfig>::make_challenge_from_buffer(chal_buf),)
    }

    pub fn create_proof_with_challenge(inter: &ZeroOneProofIntermediate<P>,
                        m: &<P as CurveConfig>::ScalarField,
                        c: &PedersenComm<P>,
                        chal: &<P as CurveConfig>::ScalarField) -> Self {

        let f = (*m) * chal + inter.a;
        Self {
            ca: inter.ca.comm,
            cb: inter.cb.comm,
            f,
            z_a: c.r * chal + inter.s,
            z_b: c.r * (*chal - f) + inter.t,
        }
    }

    pub fn verify(&self, transcript: &mut Transcript, c: &sw::Affine<P>) -> bool {
        self.add_to_transcript(transcript);
        self.verify_proof(c, &transcript.challenge_scalar(b"c")[..])
    }

    pub fn verify_proof(&self, c: &sw::Affine<P>, chal_buf: &[u8]) -> bool {
        self.verify_with_challenge(c, &<P as PedersenConfig>::make_challenge_from_buffer(chal_buf),)
    }

    pub fn verify_with_challenge(&self, c: &sw::Affine<P>, chal: &<P as CurveConfig>::ScalarField) -> bool {
        (self.ca + c.mul(*chal) == PedersenComm::new_with_both(self.f, self.z_a).comm) &&
            (self.cb + c.mul(*chal - self.f) == PedersenComm::new_with_both(<P as CurveConfig>::ScalarField::ZERO, self.z_b).comm)
    }
}

impl<P: PedersenConfig> ZeroOneProofTranscriptable for ZeroOneProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript) {
        ZeroOneProof::make_transcript(transcript, &self.ca, &self.cb);
    }
}
