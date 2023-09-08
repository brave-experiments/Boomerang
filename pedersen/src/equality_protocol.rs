//! Defines an Equality protocol for various PedersenConfig types.

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
    CurveGroup,
    short_weierstrass::{self as sw},
};

use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};

use crate::{transcript::EqualityTranscript, pedersen_config::PedersenConfig, pedersen_config::PedersenComm, transcript::CHALLENGE_SIZE};

pub struct EqualityProof<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,    
    pub z : <P as CurveConfig>::ScalarField, 
}

pub struct EqualityProofIntermediate<P: PedersenConfig> {
    pub r: <P as CurveConfig>::ScalarField,
    pub alpha : sw::Affine<P>,
}

impl<P: PedersenConfig> EqualityProof<P> {
    /// This is just to circumvent an annoying issue with Rust's current generics system. 
    pub const CHAL_SIZE: usize = CHALLENGE_SIZE;

    pub fn add_to_transcript(&self, transcript: &mut Transcript, c1: &PedersenComm<P>, c2: &PedersenComm<P>) {
        Self::make_transcript(transcript, c1, c2, &self.alpha)
    }
       
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

    pub fn create_intermediates<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          c1: &PedersenComm<P>,                                          
                                                        c2: &PedersenComm<P>) -> EqualityProofIntermediate<P> {

        let r = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = P::GENERATOR2.mul(r).into_affine();
        Self::make_transcript(transcript, c1, c2, &alpha);
        EqualityProofIntermediate {
            r: r,
            alpha: alpha
        }
    }

    pub fn create<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          c1: &PedersenComm<P>,
                                          c2: &PedersenComm<P>) -> Self {
        Self::create_proof(&Self::create_intermediates(transcript, rng, c1, c2), c1, c2, &transcript.challenge_scalar(b"c")[..])
    }

    pub fn create_proof(inter: &EqualityProofIntermediate<P>, c1: &PedersenComm<P>, c2: &PedersenComm<P>, chal_buf: &[u8]) -> Self {
        
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);        
        let z = chal * (c1.r - c2.r) + inter.r;
        EqualityProof {
            alpha: inter.alpha, 
            z: z
        }
    }

    pub fn verify(&self, transcript: &mut Transcript, c1: &PedersenComm<P>, c2: &PedersenComm<P>) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, c1, c2);
        self.verify_with_challenge(c1, c2, &transcript.challenge_scalar(b"c")[..])        
    }

    pub fn verify_with_challenge(&self, c1: &PedersenComm<P>, c2: &PedersenComm<P>, chal_buf: &[u8]) -> bool {
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        P::GENERATOR2.mul(self.z) == (c1.comm - c2.comm).mul(chal) + self.alpha            
    }
}

