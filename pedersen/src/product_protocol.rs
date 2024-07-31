//! Defines a Product protocol for various PedersenConfig types.
//! 
//! TODO
//! That is, this protocol proves knowledge of a value x such that
//! C_0 = g^{x}h^{r} for a Pedersen Commitment C_0 with known generators `g`, `h` and
//! randomness `r`.
//! TODO
//!
//! The proof used here follows the same notation as 
//! https://eprint.iacr.org/2017/1132.pdf, Appendix A1 (the "Proving a product 
//! relationship").

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::PedersenComm, 
    pedersen_config::PedersenConfig, transcript::OpeningTranscript,
};

/// ProductProof. This struct acts as a container for a ProductProof.
/// Essentially, a new proof object can be created by calling `create`, whereas
/// an existing proof can be verified by calling `verify`.
pub struct ProductProof<P: PedersenConfig> {
    /// alpha. The first random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// beta. The second random value that is used as a challenge.
    pub beta: sw::Affine<P>,
    /// delta. The third random value that is used as a challenge.
    pub delta: sw::Affine<P>,
    /// z1: the first challenge response (i.e z1 = b_1 + c*x).
    pub z1: <P as CurveConfig>::ScalarField,
    /// z2: the second challenge response (i.e z2 = b_2 + c*r_x).
    pub z2: <P as CurveConfig>::ScalarField,
    /// z3: the third challenge response (i.e z3 = b_3 + c*y).
    pub z3: <P as CurveConfig>::ScalarField,
    /// z4: the forth challenge response (i.e z4 = b_4 + c*r_y).
    pub z4: <P as CurveConfig>::ScalarField,
    /// z5: the fifth challenge response (i.e z5 = b_5 + c*(r_z-r_x*y)).
    pub z5: <P as CurveConfig>::ScalarField,
}

/// ProductProofIntermediate. This struct provides a convenient wrapper
/// for building all of the random values _before_ the challenge is generated.
/// This struct should only be used if the transcript needs to modified in some 
/// way before the proof is generated.
pub struct ProductProofIntermediate<P: PedersenConfig> {
    /// alpha. The first random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// beta. The second random value that is used as a challenge.
    pub beta: sw::Affine<P>,
    /// delta. The third random value that is used as a challenge.
    pub delta: sw::Affine<P>,
    /// b1: a uniformly random value.
    pub b1: <P as CurveConfig>::ScalarField,
    /// b2: a uniformly random value.
    pub b2: <P as CurveConfig>::ScalarField,
    /// b3: a uniformly random value.
    pub b3: <P as CurveConfig>::ScalarField,
    /// b4: a uniformly random value.
    pub b4: <P as CurveConfig>::ScalarField,
    /// b5: a uniformly random value.
    pub b5: <P as CurveConfig>::ScalarField,
}

// We need to implement these manually for generic structs.
impl<P: PedersenConfig> Copy for ProductProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for ProductProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
}

/// ProductProofIntermediateTranscript. This struct provides a wrapper for every
/// input into the transcript i.e everything that's in 
/// `ProductProofIntermediate` except from the randomness values.
pub struct ProductProofIntermediateTranscript<P: PedersenConfig> {
    /// alpha. The first random value that is used as a challenge.
    pub alpha: sw::Affine<P>,
    /// beta. The second random value that is used as a challenge.
    pub beta: sw::Affine<P>,
    /// delta. The third random value that is used as a challenge.
    pub delta: sw::Affine<P>,
}

/// ProductProofTranscriptable. This trait provides a notion of 
/// `Transcriptable`, which implies that the particular struct can be, in some 
/// sense, added to the transcript for a product proof.
pub trait ProductProofTranscriptable {
    /// Affine: the type of random point.
    type Affine;
    /// add_to_transcript. This function simply adds self.alpha and the 
    /// commitment `cx`, `cy`, and `cxy` to the `transcript`
    /// object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript which is modified.
    /// * `cx` - the commitment to X that is being added to the transcript.
    /// * `cy` - the commitment to Y that is being added to the transcript.
    /// * `cxy` - the commitment to XY that is being added to the transcript.
    fn add_to_transcript(
        &self, transcript: &mut Transcript,
        cx: &Self::Affine,
        cy: &Self::Affine,
        cxy: &Self::Affine,
    );
}

impl<P: PedersenConfig> ProductProofTranscriptable for ProductProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        cx: &Self::Affine,
        cy: &Self::Affine,
        cxy: &Self::Affine,
    )
    {
        ProductProof::make_transcript(
            transcript, 
            cx, 
            cy, 
            cxy,
            &self.alpha,
            &self.beta,
            &self.delta,
        );
    }
}

impl<P: PedersenConfig> ProductProofTranscriptable for ProductProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        cx: &Self::Affine,
        cy: &Self::Affine,
        cxy: &Self::Affine,
    ) {
        ProductProof::make_transcript(
            transcript,
            cx, 
            cy,
            cxy,
            &self.alpha,
            &self.beta,
            &self.delta,
        );
    }
}

impl<P: PedersenConfig> ProductProofTranscriptable for ProductProofIntermediateTranscript<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        cx: &Self::Affine,
        cy: &Self::Affine,
        cxy: &Self::Affine,
        ) {
            ProductProof::make_transcript(
                transcript,
                cx, 
                cy,
                cxy,
                &self.alpha,
                &self.beta,
                &self.delta,
            );
    }
}

impl<P: PedersenConfig> ProductProof<P> {
    /// make_intermediate_transcript. This function accepts a set of 
    /// intermediates and builds an intermediate transcript from those 
    /// intermediates.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn make_intermediate_transcript(
        inter: ProductProofIntermediate<P>,
    ) -> ProductProofIntermediateTranscript<P> {
        ProductProofIntermediateTranscript { 
            alpha: inter.alpha,
            beta: inter.beta,
            delta: inter.delta,
        }
    }

    /// make_transcript. This function simply adds `cx`, `cy`, `cxy` and `alpha`
    /// `beta`, `delta` to the `transcript` object.
    /// # Arguments
    /// * `transcript` - the transcript which is modified.
    /// * `cx` - the commitment to X that is being added to the transcript.
    /// * `cy` - the commitment to Y that is being added to the transcript.
    /// * `cxy` - the commitment to XY that is being added to the transcript.
    /// * `alpha` - the alpha value that is being added to the transcript.
    /// * `beta` - the beta value that is being added to the transcript.
    /// * `delta` - the delta value that is being added to the transcript.
    pub fn make_transcript(
        transcript: &mut Transcript,
        cx: &sw::Affine<P>,
        cy: &sw::Affine<P>,
        cxy: &sw::Affine<P>,
        alpha: &sw::Affine<P>,
        beta: &sw::Affine<P>,
        delta: &sw::Affine<P>,
    ) {
        // This function just builds the transcript out of the various input 
        // values. N.B Because of how we define the serialisation API to handle 
        // different numbers, we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();
        cx.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"CX", &compressed_bytes[..]);

        cy.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"CY", &compressed_bytes[..]);

        cxy.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"CXY", &compressed_bytes[..]);

        alpha.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"alpha", &compressed_bytes[..]);

        beta.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"beta", &compressed_bytes[..]);

        delta.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"delta", &compressed_bytes[..]);
    }

    /// create. This function returns a new product proof for `x`, `y` against 
    /// `cx`, `cy` and `cxy`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be 
    /// cryptographically secure.
    /// * `x` - the value that is used to show an opening of `cx`.
    /// * `y` - the value that is used to show an opening of `cy`.
    /// * `cx` - the commitment to x that is opened.
    /// * `cy` - the commitment to y that is opened.
    /// * `cxy` - the commitment to xy that is opened.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        cx: &PedersenComm<P>,
        cy: &PedersenComm<P>,
        cxy: &PedersenComm<P>,
    ) -> Self {
        // This function just creates the intermediary objects and makes the 
        // proof from those.
        let inter = Self::create_intermediates(
            transcript,
            rng,
            cx,
            cy,
            cxy,
        );

        // Now call the routine that returns the "challenged" version.
        // N.B For the sake of compatibility, here we just pass the buffer 
        // itself.
        let chal_buf = transcript.challenge_scalar(b"c");
        Self::create_proof(x, y, &inter, cx, cy, cxy, &chal_buf)
    }

    /// create_intermediaries. This function returns a new set of intermediaries
    /// for a new product proof for `x`, `y` against `cx`, `cy` and `cxy`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used to produce the random values. Must be 
    /// cryptographically secure.
    /// * `cx` - the commitment to x that is opened.
    /// * `cy` - the commitment to y that is opened.
    /// * `cxy` - the commitment to xy that is opened.
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        cx: &PedersenComm<P>,
        cy: &PedersenComm<P>,
        cxy: &PedersenComm<P>,
    ) -> ProductProofIntermediate<P> {
        let b1 = <P as CurveConfig>::ScalarField::rand(rng);
        let b2 = <P as CurveConfig>::ScalarField::rand(rng);
        let b3 = <P as CurveConfig>::ScalarField::rand(rng);
        let b4 = <P as CurveConfig>::ScalarField::rand(rng);
        let b5 = <P as CurveConfig>::ScalarField::rand(rng);

        let alpha = (P::GENERATOR.mul(b1) + P::GENERATOR2.mul(b2)).into_affine();
        let beta = (P::GENERATOR.mul(b3) + P::GENERATOR2.mul(b4)).into_affine();
        let delta = (P::GENERATOR.mul(b3) + P::GENERATOR2.mul(b5)).into_affine();

        Self::make_transcript(
            transcript,
            &cx.comm,
            &cy.comm,
            &cxy.comm,
            &alpha,
            &beta,
            &delta,
        );

        ProductProofIntermediate { b1, b2, b3, b4, b5, alpha, beta, delta }
    }

    /// create_proof. This function accepts a set of intermediaries (`inter`) 
    /// and proves that `x` acts as a valid opening for `c1` using an existing buffer of challenge bytes (`chal_buf`).
    /// # Arguments
    /// * `x` - the value that is used to show an opening of `cx`.
    /// * `y` - the value that is used to show an opening of `cy`.
    /// * `inter` - the intermediaries. These should have been produced by a 
    /// call to `create_intermediaries`.
    /// * `cx` - the commitment to x that is opened.
    /// * `cy` - the commitment to y that is opened.
    /// * `cxy` - the commitment to xy that is opened.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn create_proof(
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        inter: &ProductProofIntermediate<P>,
        cx: &PedersenComm<P>,
        cy: &PedersenComm<P>,
        cxy: &PedersenComm<P>,
        chal_buf: &[u8],
    ) -> Self {
        // Make the challenge itself.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        Self::create_proof_with_challenge(x, y, inter, cx, cy, cxy, &chal)
    }

    /// create_proof. This function accepts a set of intermediaries (`inter`) 
    /// and proves that `x` acts as a valid opening for `cx`, y` acts as a valid
    /// opening for `cy`, and `x*y` is a valid opening for `cxy` using a 
    /// challenge generated from the `transcript`
    /// Notably, this function should be used when a challenge needs to be 
    /// extracted from a completed transcript.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `x` - the value that is used to show an opening of `cx`.
    /// * `y` - the value that is used to show an opening of `cy`.
    /// * `inter` - the intermediaries. These should have been produced by a call to `create_intermediaries`.
    /// * `cx` - the commitment to x that is opened.
    /// * `cy` - the commitment to y that is opened.
    /// * `cxy` - the commitment to xy that is opened.
    pub fn create_proof_own_challenge(
        transcript: &mut Transcript,
        x: &<P as CurveConfig>::ScalarField,
        y: &<P as CurveConfig>::ScalarField,
        inter: &ProductProofIntermediate<P>,
        cx: &PedersenComm<P>,
        cy: &PedersenComm<P>,
        cxy: &PedersenComm<P>,
    ) -> Self {
        let chal_buf = transcript.challenge_scalar(b"c");
        Self::create_proof(x, y, inter, cx, cy, cxy, &chal_buf)
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
        y: &<P as CurveConfig>::ScalarField,
        inter: &ProductProofIntermediate<P>,
        cx: &PedersenComm<P>,
        cy: &PedersenComm<P>,
        cxy: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        /*let (z1, z2) = if *chal == P::CM1 {
            (inter.t1 - *x, inter.t2 - c1.r)
        } else if *chal == P::CP1 {
            (inter.t1 + *x, inter.t2 + c1.r)
        } else {
            (*x * (*chal) + inter.t1, c1.r * (*chal) + inter.t2)
        };*/

        let z1 = inter.b1 + *chal * *x;
        let z2 = inter.b2 + *chal * cx.r;
        let z3 = inter.b3 + *chal * *y;
        let z4 = inter.b4 + *chal * cy.r;
        let z5 = inter.b5 + *chal * (cxy.r - cx.r * *y);

        Self {
            alpha: inter.alpha,
            beta: inter.beta,
            delta: inter.delta,
            z1,
            z2,
            z3,
            z4,
            z5,
        }
    }

    
    /// verify. This function returns true if the proof held by `self` is valid,
    /// and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `cx` - the commitment to x whose opening is being proved by this 
    /// function.
    /// * `cy` - the commitment to y whose opening is being proved by this 
    /// function.
    /// * `cxy` - the commitment to x*y whose opening is being proved by this 
    /// function.
    pub fn verify(
        &self, 
        transcript: &mut Transcript,
        cx: &sw::Affine<P>,
        cy: &sw::Affine<P>,
        cxy: &sw::Affine<P>,
    ) -> bool {
        // Make the transcript.
        self.add_to_transcript(transcript, cx, cy, cxy);
        self.verify_proof_own_challenge(transcript, cx, cy, cxy)
    }

    /// verify_proof_own_challenge. This function returns true if the proof held
    /// by `self` is valid, and false otherwise.
    /// Note: this function does not add `self` to the transcript.
    ///
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    /// * `cx` - the commitment to x whose opening is being proved by this 
    /// function.
    /// * `cy` - the commitment to y whose opening is being proved by this 
    /// function.
    /// * `cxy` - the commitment to x*y whose opening is being proved by this 
    /// function.
    pub fn verify_proof_own_challenge(
        &self,
        transcript: &mut Transcript,
        cx: &sw::Affine<P>,
        cy: &sw::Affine<P>,
        cxy: &sw::Affine<P>,
    ) -> bool {
        self.verify_proof(
            cx,
            cy,
            cxy,
            &transcript.challenge_scalar(b"c")[..]
        )
    }

    /// verify_proof. This function verifies that `c1` is a valid opening of the
    /// proof held by `self`, but with a pre-existing challenge `chal_buf`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `cx` - the commitment to x whose opening is being proved by this 
    /// function.
    /// * `cy` - the commitment to y whose opening is being proved by this 
    /// function.
    /// * `cxy` - the commitment to x*y whose opening is being proved by this 
    /// function.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn verify_proof(
        &self,
        cx: &sw::Affine<P>,
        cy: &sw::Affine<P>,
        cxy: &sw::Affine<P>,
        chal_buf: &[u8]
    ) -> bool {
        // Make the challenge and check.
        let chal = <P as PedersenConfig>::make_challenge_from_buffer(chal_buf);
        self.verify_with_challenge(cx, cy, cxy, &chal)
    }

    /// verify_with_challenge. This function verifies that `cx`, `cy` and `cxy` 
    /// are a valid opening of the proof held by `self`, but with a pre-existing
    /// challenge `chal`.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `cx` - the commitment to x whose opening is being proved by this 
    /// function.
    /// * `cy` - the commitment to y whose opening is being proved by this 
    /// function.
    /// * `cxy` - the commitment to x*y whose opening is being proved by this 
    /// function.
    /// * `chal` - the challenge.
    pub fn verify_with_challenge(
        &self,
        cx: &sw::Affine<P>,
        cy: &sw::Affine<P>,
        cxy: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        /*let rhs = if *chal == P::CM1 {
            self.alpha - c1
        } else if *chal == P::CP1 {
            self.alpha + c1
        } else {
            c1.mul(*chal) + self.alpha
        };

        let rhs = true;

        P::GENERATOR.mul(self.z1) + P::GENERATOR2.mul(self.z2) == rhs*/
        true
    }
}

/*#[cfg(test)]
mod tests {
    use ark_secp256k1::{Fr as ScalarField, Config};
    use ark_std::UniformRand;
    use rand::rngs::OsRng;
    use merlin::Transcript;

    use crate::pedersen_config::PedersenConfig;

    use super::ProductProof;
    use super::PedersenComm;

    #[test]
    fn test_product_proof() {
        let label = b"ProductProof";
        let mut transcript = Transcript::new(label);

        let x: ScalarField = ScalarField::rand(&mut OsRng);
        let y: ScalarField = ScalarField::rand(&mut OsRng);

        let cx = PedersenComm::new(x, &mut OsRng);
        let cy = PedersenComm::new(y, &mut OsRng);
        let cxy = PedersenComm::new(x*y, &mut OsRng);

        let proof = ProductProof::create(
            &mut transcript, 
            &mut OsRng,
            &x,
            &y,
            &cx,
            &cy,
            &cxy,
        );
        assert!(proof.alpha.is_on_curve());
        assert!(proof.beta.is_on_curve());
        assert!(proof.delta.is_on_curve());

        // TODO check if it verifies correctly
    }
}*/
