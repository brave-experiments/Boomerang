//! Defines a protocol for EC point scalar multiplication.
//! Namely, this protocol proves that we know lambda * P for a known point P and an
//! unknown scalar lambda.

use ark_ec::{
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveConfig, CurveGroup,
};

use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, UniformRand};
use merlin::Transcript;

use rand::{CryptoRng, RngCore};

use crate::{
    ec_point_add_protocol::ECPointAddProof, pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig, transcript::ECScalarMulTranscript,
};

pub struct ECScalarMulProof<P: PedersenConfig> {
    pub c1: sw::Affine<<P as PedersenConfig>::OCurve>,
    pub c2: sw::Affine<P>,
    pub c3: sw::Affine<P>,
    pub c4: sw::Affine<<P as PedersenConfig>::OCurve>,
    pub c5: sw::Affine<P>,
    pub c6: sw::Affine<P>,
    pub c7: sw::Affine<P>,
    pub c8: sw::Affine<P>,

    pub z1: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    pub z2: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    pub z3: <P as CurveConfig>::ScalarField,
    pub z4: <P as CurveConfig>::ScalarField,
    pub eap: ECPointAddProof<P>,
}

impl<P: PedersenConfig> ECScalarMulProof<P> {
    const OTHER_ZERO: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField =
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField::ZERO;

    fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        c7: &sw::Affine<P>,
        c8: &sw::Affine<P>,
    ) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        ECScalarMulTranscript::domain_sep(transcript);
        let mut compressed_bytes = Vec::new();

        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C6", &compressed_bytes[..]);

        c7.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C7", &compressed_bytes[..]);

        c8.serialize_compressed(&mut compressed_bytes).unwrap();
        ECScalarMulTranscript::append_point(transcript, b"C8", &compressed_bytes[..]);
    }

    fn get_random_p<T: RngCore + CryptoRng>(
        rng: &mut T,
    ) -> <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField {
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(rng)
    }

    fn create_commit_other<T: RngCore + CryptoRng>(
        val: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        rng: &mut T,
    ) -> (
        sw::Affine<<P as PedersenConfig>::OCurve>,
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    ) {
        let r = Self::get_random_p(rng);
        (
            (<<P as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR * (*val)
                + <P as PedersenConfig>::OGENERATOR2.mul(r))
            .into_affine(),
            r,
        )
    }

    fn mul_other(
        x: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        r: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    ) -> sw::Affine<<P as PedersenConfig>::OCurve> {
        (<<P as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR * (*x)
            + <P as PedersenConfig>::OGENERATOR2.mul(r))
        .into_affine()
    }

    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        S: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // Make the various transcripts.
        // We do this by first taking lambda and committing to it over the base curve, before
        // comitting to the rest separately.
        let mut alpha = Self::get_random_p(rng);

        loop {
            if alpha != Self::OTHER_ZERO
                && alpha != *lambda
                && alpha != <P as PedersenConfig>::O_TWO * (*lambda)
            {
                break;
            }
            alpha = Self::get_random_p(rng);
        }

        let (c1, r1) = Self::create_commit_other(lambda, rng);

        let st = ((*p).mul(alpha)).into_affine();
        let s = <P as PedersenConfig>::from_ob_to_sf(st.x);
        let t = <P as PedersenConfig>::from_ob_to_sf(st.y);

        let uv = ((*p).mul(alpha - lambda)).into_affine();
        let u = <P as PedersenConfig>::from_ob_to_sf(uv.x);
        let v = <P as PedersenConfig>::from_ob_to_sf(uv.y);

        // Make the commitments.
        let c2 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(S.x), rng);
        let c3 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(S.y), rng);

        // Make c4 separately.
        let (c4, r4) = Self::create_commit_other(&alpha, rng);

        // Now the rest.
        let c5 = PedersenComm::new(s, rng);
        let c6 = PedersenComm::new(t, rng);

        let c7 = PedersenComm::new(u, rng);
        let c8 = PedersenComm::new(v, rng);

        // Make the transcript.
        Self::make_transcript(
            transcript, &c1, &c2.comm, &c3.comm, &c4, &c5.comm, &c6.comm, &c7.comm, &c8.comm,
        );

        // Because we've already generated the randomness, we now extract those values to use
        // in our challenges.
        let beta_1 = r4;
        let beta_2 = c5.r;
        let beta_3 = c6.r;
        let beta_4 = c7.r;
        let beta_5 = c8.r;

        // Now produce the challenge.
        let chal_buf = ECScalarMulTranscript::challenge_scalar(transcript, b"c");
        let c = chal_buf.last().unwrap();

        let eap = ECPointAddProof::create_with_existing_commitments(
            transcript, rng, *S, uv, st, &c2, &c3, &c7, &c8, &c5, &c6,
        );

        if c & 1 == 0 {
            Self {
                c1: c1,
                c2: c2.comm,
                c3: c3.comm,
                c4: c4,
                c5: c5.comm,
                c6: c6.comm,
                c7: c7.comm,
                c8: c8.comm,
                z1: alpha,
                z2: beta_1,
                z3: beta_2,
                z4: beta_3,
                eap,
            }
        } else {
            Self {
                c1,
                c2: c2.comm,
                c3: c3.comm,
                c4,
                c5: c5.comm,
                c6: c6.comm,
                c7: c7.comm,
                c8: c8.comm,
                z1: alpha - *lambda,
                z2: beta_1 - r1,
                z3: beta_4,
                z4: beta_5,
                eap,
            }
        }
    }

    pub fn verify(
        &self,
        transcript: &mut Transcript,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> bool {
        Self::make_transcript(
            transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6, &self.c7,
            &self.c8,
        );

        // Now produce the challenge.
        let chal_buf = ECScalarMulTranscript::challenge_scalar(transcript, b"c");
        let c = chal_buf.last().unwrap();

        let worked: bool;

        let z1_p = p.mul(&self.z1).into_affine();

        if c & 1 == 0 {
            let s_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.x);
            let t_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.y);
            worked = (self.c4 == Self::mul_other(&self.z1, &self.z2))
                && (self.c5 == PedersenComm::new_with_both(s_dash, self.z3).comm)
                && (self.c6 == PedersenComm::new_with_both(t_dash, self.z4).comm);
        } else {
            let u_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.x);
            let v_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.y);
            worked = ((self.c4 - self.c1) == Self::mul_other(&self.z1, &self.z2))
                && (self.c7 == PedersenComm::new_with_both(u_dash, self.z3).comm)
                && (self.c8 == PedersenComm::new_with_both(v_dash, self.z4).comm);
        }

        worked && self.eap.verify(transcript)
    }
}
