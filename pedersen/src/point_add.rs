//! This file defines a trait for a point addition proof.
//! More broadly, this file defines a generic trait for proving that `t = a + b` for
//! elliptic curve points `t`, `a`, `b`.
//! This trait exists to allow easier interoperability between ZKAttest code and our point addition proof.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig,
};

use crate::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

pub trait PointAddProtocol<P: PedersenConfig> {
    /// Intermediate. This type is the intermediate type for this kind of point addition proof.
    type Intermediate;

    /// IntermediateTranscript. This is the type of intermediate transcript for this kind of point addition proof.
    type IntermediateTranscript;

    /// make_intermediate_transcript. This function accepts a set of intermediates (`inter`) and builds
    /// a new intermediate transcript object from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate objects.
    fn make_intermediate_transcript(inter: Self::Intermediate) -> Self::IntermediateTranscript;

    fn challenge_scalar(transcript: &mut Transcript) -> [u8; 64];

    /// create_intermediates_with_existing_commitments. This function returns a new set of
    /// intermediaries for a proof that  `t = a + b` using already existing commitments to `a`, `b`, and `t`.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    /// * `ci` - the existing commitments.
    #[allow(clippy::too_many_arguments)]
    fn create_intermediates_with_existing_commitments<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
    ) -> Self::Intermediate;

    /// create_with_existing_commitments. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing commitments `c1,...,c6`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used. Must be cryptographically secure.
    /// * `a` - one of the summands.
    /// * `b` - the other summands.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `ci` - the commitments.  
    #[allow(clippy::too_many_arguments)]
    fn create_with_existing_commitments<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
    ) -> Self
    where
        Self: Sized,
    {
        let inter = Self::create_intermediates_with_existing_commitments(
            transcript, rng, a, b, t, c1, c2, c3, c4, c5, c6,
        );

        // Make the challenge.
        let chal_buf = Self::challenge_scalar(transcript);

        // Now just delegate to the other proof routines.
        Self::create_proof(a, b, t, &inter, c1, c2, c3, c4, c5, c6, &chal_buf)
    }

    /// create_proof. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined slice of challenge bytes (`chal_buf`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `ci` - the commitments.
    /// * `chal_buf` - the buffer that contains the challenge bytes.    
    #[allow(clippy::too_many_arguments)]
    fn create_proof(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self
    where
        Self: Sized,
    {
        // Just return the result of creating all of the sub-proofs.
        Self::create_proof_with_challenge(
            a,
            b,
            t,
            inter,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            &<P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1),
        )
    }

    /// create_proof_with_challenge. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined challenge (`chal`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `ci` - the commitments to the co-ordinates.
    /// * `chal` - the challenge point.
    #[allow(clippy::too_many_arguments)]
    fn create_proof_with_challenge(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self;

    /// create_proof_own_challenge. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also generates
    /// a new challenge from the `transcript` when generating all proofs.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.    
    #[allow(clippy::too_many_arguments)]
    fn create_proof_own_challenge(
        transcript: &mut Transcript,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
    ) -> Self
    where
        Self: Sized,
    {
        // Just return the result of creating all the sub-proofs.
        Self::create_proof(
            a,
            b,
            t,
            inter,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            &Self::challenge_scalar(transcript)[..],
        )
    }

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `ci` - the commitments.
    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) -> bool {
        self.add_proof_to_transcript(transcript, c1, c2, c3, c4, c5, c6);
        let chal_buf = Self::challenge_scalar(transcript);
        self.verify_proof(c1, c2, c3, c4, c5, c6, &chal_buf)
    }

    /// verify_proof. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge buffer (`chal_buf`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `ci` - the commitments.
    /// * `chal_buf` - the buffer containing the challenge bytes.
    #[allow(clippy::too_many_arguments)]
    fn verify_proof(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        chal_buf: &[u8],
    ) -> bool {
        // Now produce the "right" challenge object. We do this in a generic way (see the pedersen config for more)
        // but essentially we map the lowest bit of `chal_buf` to (-1, 1) (mod p).
        // Make the challenge.
        let chal = <P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1);
        self.verify_with_challenge(c1, c2, c3, c4, c5, c6, &chal)
    }

    /// verify_with_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge (`chal`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `ci` - the commitments.
    /// * `chal` - the challenge.
    #[allow(clippy::too_many_arguments)]
    fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool;

    /// verify_proof_own_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// Note: this function does not add `self` to the transcript, and instead only uses the transcript to generate
    /// the challenges.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.
    /// * `ci` - the commitments.
    #[allow(clippy::too_many_arguments)]
    fn verify_proof_own_challenge(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) -> bool {
        self.verify_proof(c1, c2, c3, c4, c5, c6, &Self::challenge_scalar(transcript))
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize;

    /// add_proof_to_transcript. This function adds the current proof object to the transcript.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript.
    /// * `ci` - the commitment values.
    #[allow(clippy::too_many_arguments)]
    fn add_proof_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    );
}
