//! Defines an Equality protocol for various PedersenConfig types.

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
    CurveGroup,
    short_weierstrass::{self as sw},
};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};

use crate::{transcript::EqualityTranscript, pedersen_config::PedersenConfig, pedersen_config::PedersenComm};

pub struct EqualityProof<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,    
    pub z : <P as CurveConfig>::ScalarField, 
}

impl<P: PedersenConfig> EqualityProof<P> {

    fn make_transcript(transcript: &mut Transcript,
                       c1: &PedersenComm<P>,
                       c2: &PedersenComm<P>,
                       alpha_p: &sw::Affine<P>) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c1.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);

        c2.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C2", &compressed_bytes[..]);

        alpha_p.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);
    }

    fn make_challenge(transcript: &mut Transcript) -> <P as CurveConfig>::ScalarField {
        <P as CurveConfig>::ScalarField::deserialize_compressed(&transcript.challenge_scalar(b"c")[..]).unwrap()
    }

    
    pub fn create<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          c1: &PedersenComm<P>,                                          
                                          c2: &PedersenComm<P>) -> EqualityProof<P> {
        
        let r = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = P::GENERATOR2.mul(r).into_affine();
        Self::make_transcript(transcript, c1, c2, &alpha);

        // Now make the challenge.
        let chal = Self::make_challenge(transcript);
        
        let z = chal * (c1.r - c2.r) + r;
        EqualityProof {
            alpha: alpha, 
            z: z
        }
    }

    pub fn verify(&self, transcript: &mut Transcript, c1: &PedersenComm<P>, c2: &PedersenComm<P>) -> bool {
        // Make the transcript.
        Self::make_transcript(transcript, c1, c2, &self.alpha);

        // Now make the challenge and check.
        let chal = Self::make_challenge(transcript);

        P::GENERATOR2.mul(self.z) == (c1.comm - c2.comm).mul(chal) + self.alpha
    }
}

