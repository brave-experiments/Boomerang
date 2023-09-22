//! Defines a protocol for the ZKAttest EC scalar multiplication protocol with Fiat-Shamir.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,
};

use merlin::Transcript;
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenConfig,
    transcript::ZKAttestFSECScalarMulTranscript,
    zk_attest_scalar_mul_protocol::{ZKAttestECScalarMulProof, ZKAttestECScalarMulTranscriptable},
};

/// FSZKAttestECScalarMulProof. This struct acts as a container for
/// the repeated (i.e Fiat-Shamir) variant of the ZKAttest Scalar multiplication
/// protocol.
pub struct FSZKAttestECScalarMulProof<P: PedersenConfig> {
    /// proofs: the sub-proofs.
    proofs: Vec<ZKAttestECScalarMulProof<P>>,
}

impl<P: PedersenConfig> FSZKAttestECScalarMulProof<P> {
    /// create. This function creates a new scalar multiplication proof for s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `s` - the secret, target point.
    /// * `rng` - the cryptographically secure RNG.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // Initialise the transcript.
        transcript.domain_sep();

        let mut intermediates = Vec::with_capacity(P::SECPARAM);        
        for _ in 0..P::SECPARAM {
            intermediates.push(ZKAttestECScalarMulProof::create_intermediates(
                transcript, rng, s, lambda, p,
            ));
        }

        // Now make the challenge.
        let chal_buf = transcript.challenge_scalar(b"c");

        let mut proofs = Vec::with_capacity(P::SECPARAM);

        for (i, c) in chal_buf.iter().enumerate() {
            let mut byte = *c;
            for j in 0..4 {
                // Extract the c0 and c1 challenges.
                let c0 = <P as PedersenConfig>::make_single_bit_challenge(byte & 1);
                let c1 = <P as PedersenConfig>::make_single_bit_challenge((byte & 2) >> 1);
                proofs.push(ZKAttestECScalarMulProof::create_proof_with_challenge(
                    s,
                    lambda,
                    p,
                    &intermediates[i * 4 + j],
                    &c0,
                    &c1,
                ));
                byte >>= 2;
            }
        }

        Self { proofs }
    }

    /// verify. This function verifies that the proof held by `self` is valid.
    /// Namely, this function checks that each individual sub-proof is correct and returns true
    /// if all proofs pass and false otherwise. This is equivalent to checking if s = λp for some publicly known point `P`
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `p` - the publicly known generator.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> bool {
        // Initialise the transcript.
        transcript.domain_sep();
        assert!(self.proofs.len() == P::SECPARAM);

        // Now use the existing elements to build up the rest of the transcript.
        for proof in &self.proofs {
            proof.add_to_transcript(transcript);
        }

        // Make the challenge.
        let chal_buf = transcript.challenge_scalar(b"c");
        // And now just check they all go through.
        let mut worked: bool = true;

        for (i, c) in chal_buf.iter().enumerate() {
            // Take the current challenge byte.
            let mut byte = *c;

            for j in 0..4 {
                // Extract the challenges.
                let c0 = <P as PedersenConfig>::make_single_bit_challenge(byte & 1);
                let c1 = <P as PedersenConfig>::make_single_bit_challenge((byte & 2) >> 1);
                worked &= self.proofs[i * 4 + j].verify_with_challenge(p, &c0, &c1);
                byte >>= 2;
            }
        }

        worked
    }
    
    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.proofs.iter().map(|p| p.serialized_size()).sum()
    }
}
