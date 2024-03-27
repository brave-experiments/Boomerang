//! Defines an Opening protocol for various PedersenConfig types.
//! That is, this protocol proves knowledge of a value x such that
//! C_0 = g^{x}h^{r} for a Pedersen Commitment C_0 with known generators `g`, `h` and
//! randomness `r`.
//!
//! The proof used here follows the same notation as https://eprint.iacr.org/2017/1132.pdf, Appendix A (the "Knowledge of Opening").
//! This is originally due to Schnorr.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::Generators, pedersen_config::PedersenComm, pedersen_config::PedersenConfig,
    transcript::OpeningTranscript,
};

/// OpeningProof. This struct acts as a container for an OpeningProof.
/// Essentially, a new proof object can be created by calling `create`, whereas
/// an existing proof can be verified by calling `verify`.
pub struct OpeningProof<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// z1: the first challenge response (i.e z1 = xc + t_1).
    pub z1: <P as CurveConfig>::ScalarField,
    /// z2: the second challenge response (i.e z2 = rc + t_2).
    pub z2: <P as CurveConfig>::ScalarField,
}

/// OpeningProofMulti. This struct acts as a container for an OpeningProofMulti.
/// Note that this is aimed to work with multi-commitments.
/// Essentially, a new proof object can be created by calling `create`, whereas
/// an existing proof can be verified by calling `verify`.
pub struct OpeningProofMulti<P: PedersenConfig> {
    /// alpha. The random values that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// z1: the first challenge response (i.e z1 = xc + a_1).
    pub z1: <P as CurveConfig>::ScalarField,
    /// z2: the second challenge response (i.e z2 = rc + t_2).
    pub z2: Vec<<P as CurveConfig>::ScalarField>,
}

/// OpeningProofIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some way
/// before the proof is generated.
pub struct OpeningProofIntermediate<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// t1: a uniformly random value.
    pub t1: <P as CurveConfig>::ScalarField,
    /// t2: a uniformly random value.
    pub t2: <P as CurveConfig>::ScalarField,
}

/// OpeningProofMultiIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some way
/// before the proof is generated.
pub struct OpeningProofMultiIntermediate<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// t1: a uniformly random value.
    pub t1: <P as CurveConfig>::ScalarField,
    /// ts: a list of uniformly random values.
    pub ts: Vec<<P as CurveConfig>::ScalarField>,
}

// We need to implement these manually for generic structs.
impl<P: PedersenConfig> Copy for OpeningProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for OpeningProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: PedersenConfig> Clone for OpeningProofMultiIntermediate<P> {
    fn clone(&self) -> Self {
        OpeningProofMultiIntermediate {
            alpha: self.alpha.clone(),
            t1: self.t1.clone(),
            ts: self.ts.clone(),
        }
    }
}

/// OpeningProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `OpeningProofIntermediate` except from
/// the randomness values.
pub struct OpeningProofIntermediateTranscript<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
}

/// OpeningProofTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can be, in some sense, added to the transcript for an opening proof.
pub trait OpeningProofTranscriptable {
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

/// OpeningProofMultiIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `OpeningProofIntermediate` except from
/// the randomness values.
pub struct OpeningProofMultiIntermediateTranscript<P: PedersenConfig> {
    /// alpha. The random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
}

/// OpeningProofMultiTranscriptable. This trait provides a notion of `Transcriptable`, which implies
/// that the particular struct can be, in some sense, added to the transcript for an opening proof.
pub trait OpeningProofMultiTranscriptable {
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

impl<P: PedersenConfig> OpeningProof<P> {
    /// make_intermediate_transcript. This function accepts a set of intermediates and builds an intermediate
    /// transcript from those intermediates.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn make_intermediate_transcript(
        inter: OpeningProofIntermediate<P>,
    ) -> OpeningProofIntermediateTranscript<P> {
        OpeningProofIntermediateTranscript { alpha: inter.alpha }
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
        x: &<P as CurveConfig>::ScalarField,
        c1: &PedersenComm<P>,
    ) -> Self {
        // This function just creates the intermediary objects and makes the proof from
        // those.
        let inter = Self::create_intermediates(transcript, rng, c1);

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
    ) -> OpeningProofIntermediate<P> {
        let t1 = <P as CurveConfig>::ScalarField::rand(rng);
        let t2 = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = (P::GENERATOR.mul(t1) + P::GENERATOR2.mul(t2)).into_affine();
        Self::make_transcript(transcript, &c1.comm, &alpha);
        OpeningProofIntermediate { t1, t2, alpha }
    }

    /// create_proof. This function accepts a set of intermediaries (`inter`) and proves
    /// that `x` acts as a valid opening for `c1` using an existing buffer of challenge bytes (`chal_buf`).
    /// # Arguments
    /// * `x` - the value that is used to show an opening of  `c1`.
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `c1` - the commitment that is opened.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn create_proof(
        x: &<P as CurveConfig>::ScalarField,
        inter: &OpeningProofIntermediate<P>,
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
        x: &<P as CurveConfig>::ScalarField,
        inter: &OpeningProofIntermediate<P>,
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
        x: &<P as CurveConfig>::ScalarField,
        inter: &OpeningProofIntermediate<P>,
        c1: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let (z1, z2) = if *chal == P::CM1 {
            (inter.t1 - *x, inter.t2 - c1.r)
        } else if *chal == P::CP1 {
            (inter.t1 + *x, inter.t2 + c1.r)
        } else {
            (*x * (*chal) + inter.t1, c1.r * (*chal) + inter.t2)
        };

        Self {
            alpha: inter.alpha,
            z1,
            z2,
        }
    }

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `c1` - the commitment whose opening is being proved by this function.
    pub fn verify(&self, transcript: &mut Transcript, c1: &sw::Affine<P>) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, c1);
        self.verify_proof_own_challenge(transcript, c1)
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
    ) -> bool {
        self.verify_proof(c1, &transcript.challenge_scalar(b"c")[..])
    }

    /// verify_proof. This function verifies that `c1` is a valid opening
    /// of the proof held by `self`, but with a pre-existing challenge `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `c1` - the commitment whose opening is being proved by this function.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn verify_proof(&self, c1: &sw::Affine<P>, chal_buf: &[u8]) -> bool {
        // Make the challenge and check.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        self.verify_with_challenge(c1, &chal)
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
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        let rhs = if *chal == P::CM1 {
            self.alpha - c1
        } else if *chal == P::CP1 {
            self.alpha + c1
        } else {
            c1.mul(*chal) + self.alpha
        };

        P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2) == rhs
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.alpha.compressed_size() + self.z1.compressed_size() + self.z2.compressed_size()
    }
}

impl<P: PedersenConfig> OpeningProofTranscriptable for OpeningProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        OpeningProof::make_transcript(transcript, c1, &self.alpha);
    }
}

impl<P: PedersenConfig> OpeningProofTranscriptable for OpeningProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        OpeningProof::make_transcript(transcript, c1, &self.alpha);
    }
}

impl<P: PedersenConfig> OpeningProofTranscriptable for OpeningProofIntermediateTranscript<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        OpeningProof::make_transcript(transcript, c1, &self.alpha);
    }
}

impl<P: PedersenConfig> OpeningProofMulti<P> {
    /// make_intermediate_transcript. This function accepts a set of intermediates and builds an intermediate
    /// transcript from those intermediates.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn make_intermediate_transcript(
        inter: OpeningProofIntermediate<P>,
    ) -> OpeningProofMultiIntermediateTranscript<P> {
        OpeningProofMultiIntermediateTranscript { alpha: inter.alpha }
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
    ) -> OpeningProofMultiIntermediate<P> {
        let mut total: sw::Affine<P> = sw::Affine::identity();
        let mut ts: Vec<<P as CurveConfig>::ScalarField> = vec![];

        for i in 0..l {
            let t = <P as CurveConfig>::ScalarField::rand(rng);
            ts.push(t);
            total = (total + gens.generators[i].mul(t)).into();
        }
        let t1 = <P as CurveConfig>::ScalarField::rand(rng);
        let alpha = (total + P::GENERATOR2.mul(t1)).into_affine();

        Self::make_transcript(transcript, &c1.comm, &alpha);
        OpeningProofMultiIntermediate { t1, ts, alpha }
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
        inter: &OpeningProofMultiIntermediate<P>,
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
        inter: &OpeningProofMultiIntermediate<P>,
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
        inter: &OpeningProofMultiIntermediate<P>,
        c1: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        let mut z2: Vec<<P as CurveConfig>::ScalarField> = vec![];
        for i in 0..x.len() {
            let tmp = x[i] * (*chal) + inter.ts[i];
            z2.push(tmp);
        }

        let z1 = c1.r * (*chal) + inter.t1;

        Self {
            alpha: inter.alpha,
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
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, c1);
        self.verify_proof_own_challenge(transcript, c1, l, gens)
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
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        self.verify_proof(c1, &transcript.challenge_scalar(b"c")[..], l, gens)
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
        chal_buf: &[u8],
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        // Make the challenge and check.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        self.verify_with_challenge(c1, &chal, l, gens)
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
        chal: &<P as CurveConfig>::ScalarField,
        l: usize,
        gens: Generators<P>,
    ) -> bool {
        let rhs = c1.mul(*chal) + self.alpha;

        let mut tmp: sw::Affine<P> = sw::Affine::identity();
        for i in 0..l {
            tmp = (tmp + gens.generators[i].mul(self.z2[i])).into();
        }

        let lhs = (tmp + P::GENERATOR2.mul(self.z1)).into_affine();

        lhs == rhs
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.alpha.compressed_size() + self.z1.compressed_size() + self.z2.compressed_size()
    }
}

impl<P: PedersenConfig> OpeningProofMultiTranscriptable for OpeningProofMulti<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        OpeningProof::make_transcript(transcript, c1, &self.alpha);
    }
}

impl<P: PedersenConfig> OpeningProofMultiTranscriptable for OpeningProofMultiIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        OpeningProof::make_transcript(transcript, c1, &self.alpha);
    }
}

impl<P: PedersenConfig> OpeningProofMultiTranscriptable
    for OpeningProofMultiIntermediateTranscript<P>
{
    type Affine = sw::Affine<P>;
    fn add_to_transcript(&self, transcript: &mut Transcript, c1: &Self::Affine) {
        OpeningProof::make_transcript(transcript, c1, &self.alpha);
    }
}
