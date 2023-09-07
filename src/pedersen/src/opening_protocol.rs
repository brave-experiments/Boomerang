//! Defines an Opening protocol for various PedersenConfig types.
//! That is, this protocol proves knowledge of a value x such that
//! C_0 = g^{x}h^{r} for a Pedersen Commitment C_0 with known generators `g`, `h` and
//! randomness `r`.

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
    CurveGroup,
    short_weierstrass::{self as sw},
};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};

use crate::{transcript::OpeningTranscript, pedersen_config::PedersenConfig, pedersen_config::PedersenComm};

pub struct OpeningProof<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,
    pub z1: <P as CurveConfig>::ScalarField,
    pub z2: <P as CurveConfig>::ScalarField,
}

impl<P: PedersenConfig> OpeningProof<P> {

    fn make_transcript(transcript: &mut Transcript,
                       c1: &sw::Affine<P>,
                       alpha_p: &sw::Affine<P>) {

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

    fn make_challenge(transcript: &mut Transcript) -> <P as CurveConfig>::ScalarField {
        <P as CurveConfig>::ScalarField::deserialize_compressed(&transcript.challenge_scalar(b"c")[..]).unwrap()
    }

    pub fn create<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          x: &<P as CurveConfig>::ScalarField,
                                          c1: &PedersenComm<P>) -> Self {

        let t1 = <P as CurveConfig>::ScalarField::rand(rng);
        let t2 = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = (P::GENERATOR.mul(t1) + P::GENERATOR2.mul(t2)).into_affine();
        Self::make_transcript(transcript, &c1.comm, &alpha);

        // Now make the challenge.
        let chal = Self::make_challenge(transcript);

        OpeningProof {
            alpha: alpha,
            z1: *x*chal + t1,
            z2: c1.r * chal + t2
        }        
    }

    pub fn verify(&self, transcript: &mut Transcript, c1: &sw::Affine<P>) -> bool {
        // Make the transcript.
        Self::make_transcript(transcript, c1, &self.alpha);

        // Now make the challenge and check.
        let chal = Self::make_challenge(transcript);

        P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2) == c1.mul(chal) + self.alpha
    }
}
