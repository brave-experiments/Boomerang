//! This file defines a trait for scalar multiplication. Essentially, this
//! trait is used to define an API for structs that act as a proof for
//! S = λP for a known point P and an unknown scalar λ.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,
};

use crate::pedersen_config::{PedersenComm, PedersenConfig};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

pub trait ScalarMulProtocol<P: PedersenConfig> {
    /// SUB_ITER. This contains the number of iterations that each challenge byte is used in.
    /// For example, the EC scalar multiplication protocol uses each byte 8 times.
    const SUB_ITER: usize;
    /// SHIFT_BY. This contains the number of bits used for each proof. For example,
    /// the EC scalar multiplication protocol uses one bit per challenge.
    const SHIFT_BY: usize;

    /// Intermediate. This type is the intermediate type for this type of scalar multiplication proof.
    type Intermediate;

    /// IntermediateTranscript. This type is the intermediate transcript type for this type of scalar multiplication
    /// proof.
    type IntermediateTranscript;

    /// initialise_transcript. This function accepts a transcript and initialises it to the domain separator state.
    /// This is typically used for generic callers.
    /// # Arguments
    /// * `transcript` - the transcript object.
    fn initialise_transcript(transcript: &mut Transcript);

    /// challenge_scalar. This function accepts a transcript and returns a 512-bit challenge.
    /// N.B The reason for the large challenge is because we expect to support (up to) 512-bits of challenge
    /// state for Fiat-Shamir challenges (this is primarily the case if one were to ever use T-521 in ZKAttest).
    /// # Arguments
    /// * `transcript` - the transcript object.
    fn challenge_scalar(transcript: &mut Transcript) -> [u8; 64];

    /// make_intermediate_transcript. This function accepts a set of intermediates (`inter`) and builds
    /// a new intermediate transcript object from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate objects.
    fn make_intermediate_transcript(inter: Self::Intermediate) -> Self::IntermediateTranscript;

    /// create_intermediates_with_existing_commitments.
    /// This function accepts a `transcript`, a cryptographically secure RNG and returns
    /// the intermediate values for a proof that  s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `rng` - the cryptographically secure RNG.
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `c1` - the commitment to lambda with randomness `r1`.
    /// * `c2` - the commitment to s.x with randomness `r2`.
    /// * `c3` - the commitment to s.y with randomness `r3`.
    #[allow(clippy::too_many_arguments)]
    fn create_intermediates_with_existing_commitments<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self::Intermediate;

    /// create_proof. This function returns a proof that s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve. Notably, this function uses a pre-supplied buffer (`chal_buf`) for creating
    /// the underlying challenge.
    /// # Arguments
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `chal_buf` - the buffer of challenge bytes.
    /// * `c1` - the commitment to lambda with randomness `r1`.
    /// * `c2` - the commitment to s.x with randomness `r2`.
    /// * `c3` - the commitment to s.y with randomness `r3`.
    #[allow(clippy::too_many_arguments)]
    fn create_proof(
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
        chal_buf: &[u8],
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self;

    /// verify. This function verifies the proof held in `self`, returns true if the proof is valid and false otherwise.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.
    /// * `p` - the publicly known point.    
    fn verify(
        &self,
        transcript: &mut Transcript,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool {
        self.add_proof_to_transcript(transcript, c1, c2, c3);
        self.verify_proof(p, &Self::challenge_scalar(transcript), c1, c2, c3)
    }

    /// verify_proof. This function verifies the proof held in `self`, returning true if the proof is valid (and false otherwise).
    /// Notably, this function builds the challenge from the bytes supplied in `chal_buf`.
    /// # Arguments
    /// * `self` - the proof object.    
    /// * `p` - the publicly known point.
    /// * `chal_buf` - the buffer containing the challenge bytes.        
    fn verify_proof(
        &self,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        chal_buf: &[u8],
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool;

    /// create_proof_with_challenge_byte. This function returns a proof that s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve. Notably, this function uses a pre-supplied challenge (`chal`) as the challenge value.    
    /// # Arguments
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `chal` - the challenge byte.
    #[allow(clippy::too_many_arguments)]
    fn create_proof_with_challenge_byte(
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
        chal: u8,
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self;

    /// verify_with_challenge_byte. This function returns true if the proof held by `self` is valid and false otherwise.
    /// In other words, this function returns true if the proof object is a valid proof of scalar multiplication.
    /// Notably, this function uses a pre-determined challenge (`chal`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `p` - the publicly known point.
    /// * `chal` - the challenge byte.
    fn verify_with_challenge_byte(
        &self,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        chal: u8,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool;

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize;

    /// add_proof_to_transcript. This function acts as an alias for the add_to_transcript function that may
    /// be realised by other means. The main idea here is that we need a type-independent way to add proofs
    /// to the transcript for the Fiat-Shamir code.
    ///
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.
    fn add_proof_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    );
}
