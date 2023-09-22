//! Defines a protocol for EC scalar multiplication with Fiat-Shamir.
//! Essentially, this protocol is a repeated variant of Construction 4.1.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,
};

use merlin::Transcript;
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenConfig,
    scalar_mul_protocol::{ECScalarMulProof, ECScalarMulProofTranscriptable},
    transcript::FSECScalarMulTranscript,
};

/// FSECScalarMulProof. This struct acts as a container for the Fiat-Shamir scalar multiplication proof.
/// Essentially, this struct can be used to create new proofs (via ```create```), and verify existing proofs (via ```verify```).
pub struct FSECScalarMulProof<P: PedersenConfig> {
    /// proofs: the sub-proofs.    
    proofs: Vec<ECScalarMulProof<P>>,
}

impl<P: PedersenConfig> FSECScalarMulProof<P> {
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
        for _ in 0..<P as PedersenConfig>::SECPARAM {
            intermediates.push(ECScalarMulProof::create_intermediates(
                transcript, rng, s, lambda, p,
            ));
        }

        // Now make the challenge.
        let chal_buf = transcript.challenge_scalar(b"c");
        let mut proofs = Vec::with_capacity(P::SECPARAM);
        
        for (i, c) in chal_buf.iter().enumerate() {
            let mut byte = *c;
            for j in 0..8 {
                // Extract the lowest bit of byte.
                let bit = byte & 1;
                // Use that to make a challenge.
                let chal = <P as PedersenConfig>::make_single_bit_challenge(bit);
                proofs.push(ECScalarMulProof::create_proof_with_challenge(
                    s,
                    lambda,
                    p,
                    &intermediates[i * 8 + j],
                    &chal,
                ));
                byte >>= 1;
            }
        }

        // And finally just return the proofs.
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

            for j in 0..8 {
                // Extract the lowest bit of byte.
                let bit = byte & 1;
                // Use that to make a challenge.
                let chal = <P as PedersenConfig>::make_single_bit_challenge(bit);
                worked &= self.proofs[i * 8 + j].verify_with_challenge(p, &chal);
                byte >>= 1;
            }
        }

        worked
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.proofs.len() * self.proofs[0].serialized_size()
    }
}
