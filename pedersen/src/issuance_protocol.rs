//! Defines an Issuance protocol for various PedersenConfig types.
//!
//! The proof used here follows the same notation as https://eprint.iacr.org/2017/1132.pdf, Appendix A (the "Knowledge of Opening").
//! This is originally due to Schnorr.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::Generators, pedersen_config::PedersenComm, pedersen_config::PedersenConfig,
    transcript::IssuanceTranscript,
};
use ark_std::Zero;

/// IssuanceProofMulti. This struct acts as a container for an IssuanceProofMulti.
/// Note that this is aimed to work with multi-commitments.
/// Essentially, a new proof object can be created by calling `create`, whereas
/// an existing proof can be verified by calling `verify`.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceProofMulti<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// alpha2. The random value that is used as a challenge.
    pub alpha2: sw::Affine<P>,
    /// z1: the first challenge response (i.e z1 = xc + a_1).
    pub z1: <P as CurveConfig>::ScalarField,
    /// z2: the second challenge responses (i.e z2 = rc + t_2).
    pub z2: Vec<<P as CurveConfig>::ScalarField>,
}

/// IssuanceProofMultiIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some way
/// before the proof is generated.
pub struct IssuanceProofMultiIntermediate<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// alpha2. The random value that is used as a challenge.
    pub alpha2: sw::Affine<P>,
    /// t1: a uniformly random value.
    pub t1: <P as CurveConfig>::ScalarField,
    /// ts: a list of uniformly random values.
    pub ts: Vec<<P as CurveConfig>::ScalarField>,
}

impl<P: PedersenConfig> Clone for IssuanceProofMultiIntermediate<P> {
    fn clone(&self) -> Self {
        IssuanceProofMultiIntermediate {
            alpha: self.alpha,
            alpha2: self.alpha2,
            t1: self.t1,
            ts: self.ts.clone(),
        }
    }
}

/// IssuanceProofMultiIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `IssuanceProofMultiIntermediate` except from
/// the randomness values.
pub struct IssuanceProofMultiIntermediateTranscript<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// alpha2. The random value that is used as a challenge.
    pub alpha2: sw::Affine<P>,
}

/// IssuanceProofMultiTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can be, in some sense, added to the transcript for an issuance proof.
pub trait IssuanceProofMultiTranscriptable {
    /// Affine: the type of random point.
    type Affine;
    /// add_to_transcript. This function simply adds self.alpha and the commitment `c1` to the `transcript`
    /// object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the commitment that is being added to the transcript.
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine);
}

impl<P: PedersenConfig> IssuanceProofMulti<P> {
    /// make_intermediate_transcript. This function accepts a set of intermediates and builds an intermediate
    /// transcript from those intermediates.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn make_intermediate_transcript(
        inter: IssuanceProofMultiIntermediate<P>,
    ) -> IssuanceProofMultiIntermediateTranscript<P> {
        IssuanceProofMultiIntermediateTranscript {
            alpha: inter.alpha,
            alpha2: inter.alpha2,
        }
    }

    /// make_transcript. This function simply adds `c1` and `alpha_p` to the `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript which is modified.
    /// * `c1` - the commitment that is being added to the transcript.
    /// * `alpha_p` - the alpha value that is being added to the transcript.
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        alpha_p: &sw::Affine<P>,
        alpha_p_2: &sw::Affine<P>,
    ) {
        // This function just builds the transcript out of the various input values.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);

        alpha_p.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);

        alpha_p_2
            .serialize_compressed(&mut compressed_bytes)
            .unwrap();
        transcript.append_point(b"alpha 2", &compressed_bytes[..]);
    }

    /// create. This function returns a new opening proof for `x` against `c1`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be cryptographically secure.
    /// * `x` - the value that is used to show an opening of  `c1`.
    /// * `c1` - the commitment that is opened.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        x: Vec<<P as CurveConfig>::ScalarField>,
        c1: &PedersenComm<P>,
        gens: Generators<P>,
    ) -> Self {
        // This function just creates the intermediary objects and makes the proof from
        // those.
        let inter = Self::create_intermediates(transcript, rng, c1, x.len(), gens);

        // Now call the routine that returns the "challenged" version.
        // N.B For the sake of compatibility, here we just pass the buffer itself.
        let chal_buf = transcript.challenge_scalar(b"c");
        Self::create_proof(x, &inter, c1, &chal_buf)
    }

    /// create_intermediaries. This function returns a new set of intermediaries
    /// for an opening proof for `x` against `c1`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be cryptographically secure.
    /// * `x` - the value that is used to show an opening of  `c1`.
    /// * `c1` - the commitment that is opened.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        c1: &PedersenComm<P>,
        l: usize,
        gens: Generators<P>,
    ) -> IssuanceProofMultiIntermediate<P> {
        let mut total: sw::Affine<P> = sw::Affine::identity();
        let mut ts: Vec<<P as CurveConfig>::ScalarField> = vec![];

        for i in 0..l {
            let t: <P as CurveConfig>::ScalarField = if i == 1 {
                <P as CurveConfig>::ScalarField::zero()
            } else {
                <P as CurveConfig>::ScalarField::rand(rng)
            };

            ts.push(t);
            total = (total + gens.generators[i].mul(t)).into();
        }
        let t1 = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = (total + P::GENERATOR2.mul(t1)).into_affine();
        let alpha2 = (P::GENERATOR.mul(ts[2])).into_affine();

        Self::make_transcript(transcript, &c1.comm, &alpha, &alpha2);
        IssuanceProofMultiIntermediate {
            t1,
            ts,
            alpha,
            alpha2,
        }
    }

    /// create_proof. This function accepts a set of intermediaries (`inter`) and proves
    /// that `x` acts as a valid opening for `c1` using an existing buffer of challenge bytes (`chal_buf`).
    /// # Arguments
    /// * `x` - the value that is used to show an opening of  `c1`.
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `c1` - the commitment that is opened.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn create_proof(
        x: Vec<<P as CurveConfig>::ScalarField>,
        inter: &IssuanceProofMultiIntermediate<P>,
        c1: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        // Make the challenge itself.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        Self::create_proof_with_challenge(x, inter, c1, &chal)
    }

    /// create_proof. This function accepts a set of intermediaries (`inter`) and proves
    /// that `x` acts as a valid opening for `c1` using a challenge generated from the `transcript`.
    /// Notably, this function should be used when a challenge needs to be extracted from a completed transcript.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `x` - the value that is used to show an opening of  `c1`.
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `c1` - the commitment that is opened.
    pub fn create_proof_own_challenge(
        transcript: &mut Transcript,
        x: Vec<<P as CurveConfig>::ScalarField>,
        inter: &IssuanceProofMultiIntermediate<P>,
        c1: &PedersenComm<P>,
    ) -> Self {
        let chal_buf = transcript.challenge_scalar(b"c");
        Self::create_proof(x, inter, c1, &chal_buf)
    }

    /// create_proof_with_challenge. This function accepts a set of intermediaries (`inter`) and proves
    /// that `x` acts as a valid opening for `c1` using an existing challenge `chal`.
    /// # Arguments
    /// * `x` - the value that is used to show an opening of  `c1`.
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `c1` - the commitment that is opened.
    /// * `chal` - the challenge.
    pub fn create_proof_with_challenge(
        x: Vec<<P as CurveConfig>::ScalarField>,
        inter: &IssuanceProofMultiIntermediate<P>,
        c1: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let mut z2: Vec<<P as CurveConfig>::ScalarField> = vec![];
        for (i, item) in x.iter().enumerate() {
            let tmp: <P as CurveConfig>::ScalarField = if i == 1 {
                <P as CurveConfig>::ScalarField::zero()
            } else {
                *item * (*chal) + inter.ts[i]
            };
            z2.push(tmp);
        }

        let z1 = c1.r * (*chal) + inter.t1;

        Self {
            alpha: inter.alpha,
            alpha2: inter.alpha2,
            z1,
            z2,
        }
    }

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `c1` - the commitment whose opening is being proved by this function.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        pk: &sw::Affine<P>,
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, c1);
        self.verify_proof_own_challenge(transcript, c1, pk, l, gens)
    }

    /// verify_proof_own_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// Note: this function does not add `self` to the transcript.
    ///
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `c1` - the commitment whose opening is being proved by this function.
    pub fn verify_proof_own_challenge(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        pk: &sw::Affine<P>,
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        self.verify_proof(c1, pk, &transcript.challenge_scalar(b"c")[..], l, gens)
    }

    /// verify_proof. This function verifies that `c1` is a valid opening
    /// of the proof held by `self`, but with a pre-existing challenge `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the commitment whose opening is being proved by this function.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn verify_proof(
        &self,
        c1: &sw::Affine<P>,
        pk: &sw::Affine<P>,
        chal_buf: &[u8],
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        // Make the challenge and check.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        self.verify_with_challenge(c1, pk, &chal, l, gens)
    }

    /// verify_with_challenge. This function verifies that `c1` is a valid opening
    /// of the proof held by `self`, but with a pre-existing challenge `chal`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the commitment whose opening is being proved by this function.
    /// * `chal` - the challenge.
    pub fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        pk: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        // first proof

        let rhs1 = pk.mul(*chal) + self.alpha2;
        let lhs1 = P::GENERATOR.mul(self.z2[2]);

        // second proof
        let rhs = c1.mul(*chal) + self.alpha;

        let mut tmp: sw::Affine<P> = sw::Affine::identity();
        for i in 0..l {
            if i == 1 {
                continue; // We assume that x[1] = 0
            }
            tmp = (tmp + gens.generators[i].mul(self.z2[i])).into();
        }

        let lhs = (tmp + P::GENERATOR2.mul(self.z1)).into_affine();

        lhs == rhs && lhs1 == rhs1
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.alpha.compressed_size() + self.z1.compressed_size() + self.z2.compressed_size()
    }
}

impl<P: PedersenConfig> IssuanceProofMultiTranscriptable for IssuanceProofMulti<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        IssuanceProofMulti::make_transcript(transcript, c1, &self.alpha, &self.alpha2);
    }
}

impl<P: PedersenConfig> IssuanceProofMultiTranscriptable for IssuanceProofMultiIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        IssuanceProofMulti::make_transcript(transcript, c1, &self.alpha, &self.alpha2);
    }
}

impl<P: PedersenConfig> IssuanceProofMultiTranscriptable
    for IssuanceProofMultiIntermediateTranscript<P>
{
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        IssuanceProofMulti::make_transcript(transcript, c1, &self.alpha, &self.alpha2);
    }
}
