//! Defines a protocol for proof of multiplication.
//! That is, let p be a prime and let x, y be two values in F_p.
//! This protocol proves that C_3 is a Pedersen commitment to z = x * y (over F_p)

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
    CurveGroup,
    short_weierstrass::{self as sw},
};

use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};

use crate::{transcript::MulTranscript, pedersen_config::PedersenConfig, pedersen_config::PedersenComm, transcript::CHALLENGE_SIZE};

pub struct MulProof<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,
    pub beta: sw::Affine<P>,
    pub delta: sw::Affine<P>,

    pub z1: <P as CurveConfig>::ScalarField,
    pub z2: <P as CurveConfig>::ScalarField,
    pub z3: <P as CurveConfig>::ScalarField,
    pub z4: <P as CurveConfig>::ScalarField,
    pub z5: <P as CurveConfig>::ScalarField,    
}

pub struct MulProofIntermediate<P: PedersenConfig> {
    pub alpha: sw::Affine<P>,
    pub beta: sw::Affine<P>,
    pub delta: sw::Affine<P>,
    
    pub b1: <P as CurveConfig>::ScalarField,
    pub b2: <P as CurveConfig>::ScalarField,
    pub b3: <P as CurveConfig>::ScalarField,
    pub b4: <P as CurveConfig>::ScalarField,
    pub b5: <P as CurveConfig>::ScalarField,   
}

impl <P: PedersenConfig> MulProof<P> {
    /// This is just to circumvent an annoying issue with Rust's current generics system. 
    pub const CHAL_SIZE: usize = CHALLENGE_SIZE;

    pub fn add_to_transcript(&self, transcript: &mut Transcript, c1: &sw::Affine<P><P>,
                       c2: &sw::Affine<P><P>,
                             c3: &sw::Affine<P><P>) {        
        Self::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta)
    }
    
    fn make_transcript(transcript: &mut Transcript,
                       c1: &sw::Affine<P>,
                       c2: &sw::Affine<P>,
                       c3: &sw::Affine<P>,
                       alpha: &sw::Affine<P>,
                       beta: &sw::Affine<P>,
                       delta: &sw::Affine<P>) {

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
    
    pub fn create<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          x:  &<P as CurveConfig>::ScalarField,
                                          y:  &<P as CurveConfig>::ScalarField,
                                          c1: &PedersenComm<P>,
                                          c2: &PedersenComm<P>,
                                          c3: &PedersenComm<P>) -> Self {        
        Self::create_proof(x, y, &Self::create_intermediates(transcript, rng, c1, c2, c3), c1, c2, c3, &transcript.challenge_scalar(b"c")[..])            
    }

    pub fn create_intermediates<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                                        rng: &mut T,                                                        
                                                        c1: &PedersenComm<P>,
                                                        c2: &PedersenComm<P>,
                                                        c3: &PedersenComm<P>) -> MulProofIntermediate<P> {
        // Generate the random values.
        let b1 = <P as CurveConfig>::ScalarField::rand(rng);
        let b2 = <P as CurveConfig>::ScalarField::rand(rng);
        let b3 = <P as CurveConfig>::ScalarField::rand(rng);
        let b4 = <P as CurveConfig>::ScalarField::rand(rng);
        let b5 = <P as CurveConfig>::ScalarField::rand(rng);

        let alpha = (P::GENERATOR.mul(b1) + P::GENERATOR2.mul(b2)).into_affine();
        let beta  = (P::GENERATOR.mul(b3) + P::GENERATOR2.mul(b4)).into_affine();
        let delta = (c1.comm.mul(b3) + P::GENERATOR2.mul(b5)).into_affine();

        Self::make_transcript(transcript, &c1.comm, &c2.comm, &c3.comm, &alpha, &beta, &delta);

        MulProofIntermediate { b1: b1, b2: b2, b3: b3, b4: b4, b5: b5, alpha: alpha, beta: beta, delta: delta }        
    }

    pub fn create_proof(x: &<P as CurveConfig>::ScalarField, y: &<P as CurveConfig>::ScalarField,
                        inter: &MulProofIntermediate<P>,
                        c1: &PedersenComm<P>,
                        c2: &PedersenComm<P>,
                        c3: &PedersenComm<P>,
                        chal_buf: &[u8]) -> Self {

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
            z5: inter.b5 + chal * (c3.r - (c1.r*(y)))
        }        
    }

    pub fn verify(&self, transcript: &mut Transcript, c1: &sw::Affine<P>, c2: &sw::Affine<P>, c3: &sw::Affine<P>) -> bool {
        Self::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta);
        self.verify_with_challenge(c1, c2, c3, &transcript.challenge_scalar(b"c")[..])
    }


    pub fn verify_with_challenge(&self, c1: &sw::Affine<P>, c2: &sw::Affine<P>, c3: &sw::Affine<P>, chal_buf: &[u8]) -> bool {
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);        
        (self.alpha + c1.mul(chal) == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2)) &&
            (self.beta + c2.mul(chal) == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4)) &&
            (self.delta + c3.mul(chal) == c1.mul(self.z3) + P::GENERATOR2.mul(self.z5))        
    }
}
