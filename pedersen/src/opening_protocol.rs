//! Defines an Opening protocol for various PedersenConfig types.
//! That is, this protocol proves knowledge of a value x such that
//! C_0 = g^{x}h^{r} for a Pedersen Commitment C_0 with known generators `g`, `h` and
//! randomness `r`.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenComm, pedersen_config::PedersenConfig, transcript::OpeningTranscript,
    transcript::CHALLENGE_SIZE,
};

pub struct OpeningProof<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,
    pub z1: <P as CurveConfig>::ScalarField,
    pub z2: <P as CurveConfig>::ScalarField,
}

pub struct OpenProofIntermediate<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,
    pub t1: <P as CurveConfig>::ScalarField,
    pub t2: <P as CurveConfig>::ScalarField,
}

impl<P: PedersenConfig> OpeningProof<P> {
    /// This is just to circumvent an annoying issue with Rust's current generics system.
    pub const CHAL_SIZE: usize = CHALLENGE_SIZE;

    pub fn add_to_transcript(&self, transcript: &mut Transcript, c1: &sw::Affine<P>) {
        Self::make_transcript(transcript, c1, &self.alpha)
    }

    fn make_transcript(transcript: &mut Transcript, c1: &sw::Affine<P>, alpha_p: &sw::Affine<P>) {
        // This function just builds the transcript out of the various input values.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);

        alpha_p.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);
    }

    fn make_challenge_from_buffer(chal_buf: &[u8]) -> <P as CurveConfig>::ScalarField {
        <P as CurveConfig>::ScalarField::deserialize_compressed(chal_buf).unwrap()
    }

    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        x: &<P as CurveConfig>::ScalarField,
        c1: &PedersenComm<P>,
    ) -> Self {
        let inter = Self::create_intermediates(transcript, rng, c1);

        // Now call the routine that returns the "challenged" version.
        // N.B For the sake of compatibility, here we just pass the buffer itself.
        let chal_buf = transcript.challenge_scalar(b"c");
        Self::create_proof(x, &inter, c1, &chal_buf)
    }

    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        c1: &PedersenComm<P>,
    ) -> OpenProofIntermediate<P> {
        let t1 = <P as CurveConfig>::ScalarField::rand(rng);
        let t2 = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = (P::GENERATOR.mul(t1) + P::GENERATOR2.mul(t2)).into_affine();
        Self::make_transcript(transcript, &c1.comm, &alpha);

        OpenProofIntermediate {
            t1: t1,
            t2: t2,
            alpha: alpha,
        }
    }

    pub fn create_proof(
        x: &<P as CurveConfig>::ScalarField,
        inter: &OpenProofIntermediate<P>,
        c1: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        // Make the challenge itself.
        let chal = Self::make_challenge_from_buffer(chal_buf);
        Self {
            alpha: inter.alpha,
            z1: *x * chal + inter.t1,
            z2: c1.r * chal + inter.t2,
        }
    }

    pub fn verify(&self, transcript: &mut Transcript, c1: &sw::Affine<P>) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, c1);

        // Now check make the challenge and delegate.
        self.verify_with_challenge(c1, &transcript.challenge_scalar(b"c")[..])
    }

    pub fn verify_with_challenge(&self, c1: &sw::Affine<P>, chal_buf: &[u8]) -> bool {
        // Make the challenge and check.
        let chal = Self::make_challenge_from_buffer(chal_buf);
        P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2) == c1.mul(chal) + self.alpha
    }
}
