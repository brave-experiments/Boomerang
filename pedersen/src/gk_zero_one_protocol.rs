//! Defines a protocol for proving a commitment to 0 or 1 for various PedersenConfig types.
//! Specifically, this protocol shows in ZK that a particular commitment is a commitment to either 0 or 1.
//! This protocol uses the same language as https://eprint.iacr.org/2014/764.pdf, Figure 1, but the protocol
//! likely predates that work.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,
};
use merlin::Transcript;

use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use rand::{CryptoRng, RngCore};
use std::ops::Mul;

use crate::{
    pedersen_config::{PedersenComm, PedersenConfig},
    transcript::GKZeroOneTranscript,
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
    /// * `c` - the pre-existing commitment to `m`.
    fn add_to_transcript(&self, transcript: &mut Transcript, c: &Self::Affine);
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

// We need to implement these manually for generic structs.
impl<P: PedersenConfig> Copy for ZeroOneProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for ZeroOneProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
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
    /// make_intermediate_tarnscript. This function accepts a set of intermediate values and converts it into a
    /// immediate transcript for a ZeroOneProof.
    /// # Arguments
    /// * `inter` - the set of intermediate values.
    pub fn make_intermediate_transcript(
        inter: ZeroOneProofIntermediate<P>,
    ) -> ZeroOneProofIntermediateTranscript<P> {
        ZeroOneProofIntermediateTranscript {
            ca: inter.ca.comm,
            cb: inter.cb.comm,
        }
    }

    /// make_transcript. This function just adds the affine commitments `ca`, `cb` to the
    /// `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `ca` - the ca commitment.
    /// * `cb` - the cb commitment.
    /// * `c` - the existing commitment to `m`.
    pub fn make_transcript(
        transcript: &mut Transcript,
        ca: &sw::Affine<P>,
        cb: &sw::Affine<P>,
        c: &sw::Affine<P>,
    ) {
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"c0", &compressed_bytes[..]);

        ca.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"ca", &compressed_bytes[..]);

        cb.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"cb", &compressed_bytes[..]);
    }

    /// create_intermediates. This function creates a new set of intermediate values for the zero/one proof.
    /// This function should be called before a challenge is generated.
    /// # Arguments
    /// * `transcript` - the transcript object. The intermediate commitments are added to this transcript.
    /// * `rng` - the random number generator to use. Must be cryptographically random.
    /// * `m` - the 0/1 value to which we are committing.
    /// * `c` - a pre-existing commitment to `m`.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        m: &<P as CurveConfig>::ScalarField,
        c: &PedersenComm<P>,
    ) -> ZeroOneProofIntermediate<P> {
        // Make the initial random values.
        let a = <P as CurveConfig>::ScalarField::rand(rng);
        let s = <P as CurveConfig>::ScalarField::rand(rng);
        let t = <P as CurveConfig>::ScalarField::rand(rng);

        let ca = PedersenComm::new_with_both(a, s);
        let cb = PedersenComm::new_with_both(a * m, t);

        // Add them to the transcript and then just return the intermediate object.
        Self::make_transcript(transcript, &ca.comm, &cb.comm, &c.comm);
        ZeroOneProofIntermediate { ca, cb, a, s, t }
    }

    /// create. This function creates a new ZeroOneProof on `m`, returning the result.
    /// # Arguments
    /// * `transcript` - the transcript object. The intermediate commitments etc are added to this transcript.
    /// * `rng` - the random number generator to use. Must be cryptographically random.
    /// * `m` - the 0/1 value to which we are committing.
    /// * `c` - a pre-existing commitment to `m`.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        m: &<P as CurveConfig>::ScalarField,
        c: &PedersenComm<P>,
    ) -> Self {
        Self::create_proof(
            &Self::create_intermediates(transcript, rng, m, c),
            m,
            c,
            &transcript.challenge_scalar(b"c")[..],
        )
    }

    /// create_proof. This function returns a new ZeroOneProof on `m`, returning the result. Note that this
    /// function uses the challenge in `chal_buf` to generate the proof.
    /// # Arguments
    /// * `inter` - the intermediate values.
    /// * `m` - the 0/1 value to which we are committing.
    /// * `c` - a pre-existing commitment to `m`.
    /// * `chal_buf` - a buffer of existing challenge bytes.
    pub fn create_proof(
        inter: &ZeroOneProofIntermediate<P>,
        m: &<P as CurveConfig>::ScalarField,
        c: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        Self::create_proof_with_challenge(
            inter,
            m,
            c,
            &<P as PedersenConfig>::make_challenge_from_buffer(chal_buf),
        )
    }

    /// create_proof_with_challenge. This function returns a new ZeroOneProof on `m`, returning the result. Note that this
    /// function uses the challenge `chal` to generate the proof.
    /// # Arguments
    /// * `inter` - the intermediate values.
    /// * `m` - the 0/1 value to which we are committing.
    /// * `c` - a pre-existing commitment to `m`.
    /// * `chal` - a pre-existing challenge.    
    pub fn create_proof_with_challenge(
        inter: &ZeroOneProofIntermediate<P>,
        m: &<P as CurveConfig>::ScalarField,
        c: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let f = (*m) * chal + inter.a;
        Self {
            ca: inter.ca.comm,
            cb: inter.cb.comm,
            f,
            z_a: c.r * chal + inter.s,
            z_b: c.r * (*chal - f) + inter.t,
        }
    }

    /// verify. This function verifies that the proof held by `self` is valid, returning true if so.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.
    /// * `c` - the already-received commitment to `m`.
    pub fn verify(&self, transcript: &mut Transcript, c: &sw::Affine<P>) -> bool {
        self.add_to_transcript(transcript, c);
        self.verify_proof(c, &transcript.challenge_scalar(b"c")[..])
    }

    /// verify_proof. This function verifies that the proof held by `self` is valid, returning true if so.
    /// This function uses the challenge bytes `chal_buf` to make the challenge.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `c` - the already-received commitment to `m`.
    /// * `chal_buf` - the challenge bytes to use.
    pub fn verify_proof(&self, c: &sw::Affine<P>, chal_buf: &[u8]) -> bool {
        self.verify_with_challenge(
            c,
            &<P as PedersenConfig>::make_challenge_from_buffer(chal_buf),
        )
    }

    /// verify_proof. This function verifies that the proof held by `self` is valid, returning true if so.
    /// This function uses the challenge `chal`.    
    /// # Arguments
    /// * `self` - the proof object.
    /// * `c` - the already-received commitment to `m`.
    /// * `chal` - the challenge to use.
    pub fn verify_with_challenge(
        &self,
        c: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        (self.ca + c.mul(*chal) == PedersenComm::new_with_both(self.f, self.z_a).comm)
            && (self.cb + c.mul(*chal - self.f)
                == PedersenComm::new_with_both(<P as CurveConfig>::ScalarField::ZERO, self.z_b)
                    .comm)
    }
}

impl<P: PedersenConfig> ZeroOneProofTranscriptable for ZeroOneProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c: &Self::Affine) {
        ZeroOneProof::make_transcript(transcript, &self.ca, &self.cb, c);
    }
}

impl<P: PedersenConfig> ZeroOneProofTranscriptable for ZeroOneProofIntermediateTranscript<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c: &Self::Affine) {
        ZeroOneProof::make_transcript(transcript, &self.ca, &self.cb, c);
    }
}

impl<P: PedersenConfig> ZeroOneProofTranscriptable for ZeroOneProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c: &Self::Affine) {
        ZeroOneProof::make_transcript(transcript, &self.ca.comm, &self.cb.comm, c);
    }
}
