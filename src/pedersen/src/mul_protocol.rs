//! Defines a protocol for proof of multiplication.
//! That is, let p be a prime and let x, y be two values in F_p.
//! This protocol proves that C_3 is a Pedersen commitment to z = x * y (over F_p)

use merlin::Transcript;
use ark_ec::{
    CurveConfig,
    CurveGroup,
    short_weierstrass::{self as sw},
};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};

use crate::{transcript::MulTranscript, pedersen_config::PedersenConfig, pedersen_config::PedersenComm};

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

impl <P: PedersenConfig> MulProof<P> {

    fn make_transcript(transcript: &mut Transcript,
                       c1: &PedersenComm<P>,
                       c2: &PedersenComm<P>,
                       c3: &PedersenComm<P>,
                       alpha: &sw::Affine<P>,
                       beta: &sw::Affine<P>,
                       delta: &sw::Affine<P>) {

        // This function just builds the transcript out of the various input values.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c1.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);
        
        c2.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C2", &compressed_bytes[..]);

        c3.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C3", &compressed_bytes[..]);

        alpha.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);

        beta.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"beta", &compressed_bytes[..]);

        delta.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"delta", &compressed_bytes[..]);        
    }


    fn make_challenge(transcript: &mut Transcript) -> <P as CurveConfig>::ScalarField {
        <P as CurveConfig>::ScalarField::deserialize_compressed(&transcript.challenge_scalar(b"c")[..]).unwrap()
    }
    
    pub fn create<T: RngCore + CryptoRng>(transcript: &mut Transcript,
                                          rng: &mut T,
                                          x: <P as CurveConfig>::ScalarField,
                                          y: <P as CurveConfig>::ScalarField,
                                          c1: &PedersenComm<P>,
                                          c2: &PedersenComm<P>,
                                          c3: &PedersenComm<P>) -> Self {

        // Generate the random values.
        let b1 = <P as CurveConfig>::ScalarField::rand(rng);
        let b2 = <P as CurveConfig>::ScalarField::rand(rng);
        let b3 = <P as CurveConfig>::ScalarField::rand(rng);
        let b4 = <P as CurveConfig>::ScalarField::rand(rng);
        let b5 = <P as CurveConfig>::ScalarField::rand(rng);

        let alpha = (P::GENERATOR.mul(b1) + P::GENERATOR2.mul(b2)).into_affine();
        let beta  = (P::GENERATOR.mul(b3) + P::GENERATOR2.mul(b4)).into_affine();
        let delta = (c1.comm.mul(b3) + P::GENERATOR2.mul(b5)).into_affine();

        Self::make_transcript(transcript, c1, c2, c3, &alpha, &beta, &delta);

        // Now make the challenge.
        let chal = Self::make_challenge(transcript);
        
        Self {
            alpha: alpha,
            beta: beta,
            delta: delta,
            z1: b1 + (chal * (x)),
            z2: b2 + (chal * c1.r),
            z3: b3 + (chal * (y)),
            z4: b4 + (chal * c2.r),
            z5: b5 + chal * (c3.r - (c1.r*(y)))
        }        
    }

    pub fn verify(&self, transcript: &mut Transcript, c1: &PedersenComm<P>, c2: &PedersenComm<P>, c3: &PedersenComm<P>) -> bool {
        Self::make_transcript(transcript, c1, c2, c3, &self.alpha, &self.beta, &self.delta);
        let chal = Self::make_challenge(transcript);
        
        (self.alpha + c1.comm.mul(chal) == P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2)) &&
            (self.beta + c2.comm.mul(chal) == P::GENERATOR.mul(self.z3) + P::GENERATOR2.mul(self.z4)) &&
            (self.delta + c3.comm.mul(chal) == c1.comm.mul(self.z3) + P::GENERATOR2.mul(self.z5))        
    }
}
