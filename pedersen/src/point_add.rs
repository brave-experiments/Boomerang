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

    /// create_intermediates. This function returns a new set of intermediaries for a proof that
    /// `t = a + b` using already existing commitments to `a`, `b`, and `t`. This function
    /// will generate new commitments to `a`, `b`, and `t`.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self::Intermediate;

    /// create_intermediates_with_existing_commitments. This function returns a new set of
    /// intermediaries for a proof that  `t = a + b` using already existing commitments to `a`, `b`, and `t`.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    /// * `c1` - the commitment to a.x.
    /// * `c2` - the commitment to a.y.
    /// * `c3` - the commitment to b.x.
    /// * `c4` - the commitment to a.y.
    /// * `c5` - the commitment to t.x.
    /// * `c6` - the commitment to t.y.
    /// * `stored_comms` - true if this intermediate should be seen as storing the commitments, false otherwise.
    #[allow(clippy::too_many_arguments)]
    fn create_intermediates_with_existing_commitments<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        _t: sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
        stored_comms: bool,
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
    ) -> Self;

    /// create_proof. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined slice of challenge bytes (`chal_buf`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    fn create_proof(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
        chal_buf: &[u8],
    ) -> Self;

    /// create_proof_with_challenge. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined challenge (`chal`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `chal` - the challenge point.
    fn create_proof_with_challenge(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
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
    fn create_proof_own_challenge(
        transcript: &mut Transcript,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &Self::Intermediate,
    ) -> Self;

    /// create. This function returns a new proof of elliptic curve addition point addition
    /// for `t = a + b`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used. Must be cryptographically secure.
    /// * `a` - one of the summands.
    /// * `b` - the other summands.
    /// * `t` - the target point (i.e `t = a + b`).
    fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self;

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    fn verify(&self, transcript: &mut Transcript) -> bool;

    /// verify_proof. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge buffer (`chal_buf`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `chal_buf` - the buffer containing the challenge bytes.
    fn verify_proof(&self, chal_buf: &[u8]) -> bool;

    /// verify_with_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge (`chal`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `chal` - the challenge.
    fn verify_with_challenge(&self, chal: &<P as CurveConfig>::ScalarField) -> bool;

    /// verify_proof_own_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// Note: this function does not add `self` to the transcript, and instead only uses the transcript to generate
    /// the challenges.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.
    fn verify_proof_own_challenge(&self, transcript: &mut Transcript) -> bool;

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize;

    /// add_proof_to_transcript. This function adds the current proof object to the transcript.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript.
    fn add_proof_to_transcript(&self, transcript: &mut Transcript);
}
