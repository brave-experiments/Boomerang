//! Defines a protocol for EC point scalar multiplication.
//! Namely, this protocol proves that we know S = λP for a known point P and an
//! unknown scalar λ.
//! The particular proof implemented in this file is the same as the proof presented in
//! Construction 4.1 (CDLS).

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

/// ECScalarMulProof. This struct acts as a container for the Scalar multiplication proof.
/// Essentially, this struct can be used to create new proofs (via ```create```), and verify
/// existing proofs (via ```verify```).
/// In this documentation we use the convention of S = λP, and that each commitment C_i has associated
/// randomness r_i.
pub struct ECScalarMulProof<P: PedersenConfig> {
    /// c1: the commitment to λ. This commitment is made over the original curve, and not the T curve.
    pub c1: sw::Affine<<P as PedersenConfig>::OCurve>,
    /// c2: the commitment to the x co-ordinate of S.
    pub c2: sw::Affine<P>,
    /// c3: the commitment to the y co-ordinate of S.
    pub c3: sw::Affine<P>,
    /// c4: the commitment to the random value α.
    pub c4: sw::Affine<<P as PedersenConfig>::OCurve>,
    /// c5: the commitment to the x co-ordinate of αP.
    pub c5: sw::Affine<P>,
    /// c6: the commitment to the y co-ordinate of αP.
    pub c6: sw::Affine<P>,
    /// c7: the commitment to the x co-ordinate of (α-λ)P.
    pub c7: sw::Affine<P>,
    /// c8: the commitment to the y co-ordinate of (α-λ)P.
    pub c8: sw::Affine<P>,

    /// z1: the z1 portion of the response. This is α if c == 0 and (α-λ) if c == 1.
    pub z1: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    /// z2: the z2 portion of the response. This is β_1 if c == 0 and β_1 - r_1 if c == 1.
    pub z2: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    /// z3: the z3 portion of the response. This is β_2 if c == 0 and β_4 if c == 1.
    pub z3: <P as CurveConfig>::ScalarField,
    /// z3: the z3 portion of the response. This is β_4 if c == 0 and β_5 if c == 1.
    pub z4: <P as CurveConfig>::ScalarField,
    /// eap: the elliptic curve addition proof. This proof is used to show that
    /// αP = λP + ((α-λ)P).
    pub eap: ECPointAddProof<P>,
}

impl<P: PedersenConfig> ECScalarMulProof<P> {
    /// OTHER_ZERO. This constant is used to act as the zero element for the ScalarField of
    /// OCurve. This is here primarily because the proof formation needs it when choosing α.
    const OTHER_ZERO: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField =
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField::ZERO;

    #[allow(clippy::too_many_arguments)]
    /// make_transcript. This function accepts a `transcript`, alongside all auxiliary commitments (`c1`,..., `c8`)
    /// and incorporates each commitment into the transcript.
    /// # Arguments
    /// * `transcript` - the transcript object to which the commitments are added.
    /// * `ci` - the commitments. These are detailed in the ECScalarMulProof struct documentation.
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
    #[deny(clippy::too_many_arguments)]

    /// get_random_p. This function is a helper function for returning a random value from
    /// the scalar field of the OCurve.
    /// # Arguments
    /// * `rng` - the random number generator used to produce the random value. Must be a cryptographically
    /// secure RNG.
    /// Returns a random scalar value from OCurve::ScalarField.
    fn get_random_p<T: RngCore + CryptoRng>(
        rng: &mut T,
    ) -> <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField {
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(rng)
    }

    /// create_commit_other. This function accepts a value (`val` ∈ OCurve::ScalarField)
    /// and produces a new Pedersen Commitment C = val*g + r*h, where `g`, `h` are public
    /// generators of OCurve and `r` is a random element of OCurve::ScalarField.
    /// # Arguments
    /// * `val - the value that is being committed to.
    /// * `rng` - the random number generator used to produce the random value. Must be a cryptographically
    /// secure RNG.
    /// Returns a new commitment to `val` as a tuple.
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

    /// new_other_with_both. This function accepts two values `x`, `r` ∈ OCurve::ScalarField
    /// and uses them to form a new Pedersen Commitment in Self::Curve. Namely, this function
    /// returns C = xg + rh, where `g` and `r` are publicly known generators of Self::Curve.
    /// # Arguments
    /// * `x` - the value that is being committed to.
    /// * `r` - the randomness value that is being used.
    fn new_other_with_both(
        x: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        r: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    ) -> sw::Affine<<P as PedersenConfig>::OCurve> {
        (<<P as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR * (*x)
            + <P as PedersenConfig>::OGENERATOR2.mul(r))
        .into_affine()
    }

    /// create. This function accepts a `transcript`, a cryptographically secure RNG and returns a proof that
    /// s = λp for some publicly known point `P`. Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve.
    /// # Arguments
    /// * `transcript` - the transcript object to use.
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // Part 1: make the various commitments.
        // To begin, we commit to lambda.
        let (c1, r1) = Self::create_commit_other(lambda, rng);

        // and now we make the unique alpha value. We repeat until we've
        // found the right value. Note that whp we do not expect this loop to repeat
        // many times, as the probability of choosing α ∈ {0, λ, 2λ} is pretty small.
        let mut alpha = Self::get_random_p(rng);

        loop {
            if alpha != Self::OTHER_ZERO && alpha != *lambda && alpha != (*lambda).double() {
                break;
            }
            alpha = Self::get_random_p(rng);
        }

        // Now we compute the co-ordinates of αP.
        // N.B This differs from the paper: to prevent re-using `s` (even across cases)
        // we label the co-ordinates of αP = (apx, apy).
        let ap = ((*p).mul(alpha)).into_affine();
        let apx = <P as PedersenConfig>::from_ob_to_sf(ap.x);
        let apy = <P as PedersenConfig>::from_ob_to_sf(ap.y);

        // We now do the same with (α-λ)P. We label (α-λ)P = amlp = (amplx, amply).
        let amlp = ((*p).mul(alpha - lambda)).into_affine();
        let amlpx = <P as PedersenConfig>::from_ob_to_sf(amlp.x);
        let amlpy = <P as PedersenConfig>::from_ob_to_sf(amlp.y);

        // And now we finally can commit to things.
        // As in the paper, c2 is a commitment to the x co-ordinate of `s`, and
        // c3 is a commitment to the y co-ordinate of `s` (i.e c2 = Comm_{q}(s.x), c3 = Comm_{q}(s.y).
        let c2 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(s.x), rng);
        let c3 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(s.y), rng);

        // c4 = Comm_{p}(α).
        let (c4, r4) = Self::create_commit_other(&alpha, rng);

        // c5 = Comm_{p}(apx), c6 = Comm_{p}(apy).
        let c5 = PedersenComm::new(apx, rng);
        let c6 = PedersenComm::new(apy, rng);

        // c7 = Comm_{q}(amlx), c8 = Comm_{q}(amly).
        let c7 = PedersenComm::new(amlpx, rng);
        let c8 = PedersenComm::new(amlpy, rng);

        // Part 2: make the transcript and the proof itself.
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

        // Now produce the challenge. Here we only use a single bit (c) to match the
        // CDLS construction.
        let chal_buf = ECScalarMulTranscript::challenge_scalar(transcript, b"c");
        let c = chal_buf.last().unwrap() & 1;

        // Prove that αP = λP + ((α-λ)P) using our existing commitments.
        let eap = ECPointAddProof::create_with_existing_commitments(
            transcript, rng, *s, amlp, ap, &c2, &c3, &c7, &c8, &c5, &c6,
        );

        // And, finally, construct the proof.
        // Note that c can only be 0 or 1 here.
        if c == 0 {
            Self {
                c1,
                c2: c2.comm,
                c3: c3.comm,
                c4,
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

    /// verify. This function verifies that the proof in `self` holds. This function returns
    /// true in case of success and false otherwise.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the stateful transcript object.
    /// * `p` - the publicly known point.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> bool {
        // Part 1: restore the transcript from the known values.
        Self::make_transcript(
            transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6, &self.c7,
            &self.c8,
        );

        // Now produce the challenge. As before, we only use the lowest bit.
        let chal_buf = ECScalarMulTranscript::challenge_scalar(transcript, b"c");
        let c = chal_buf.last().unwrap() & 1;

        // z1_p = z1P, which is used in both verifier computations.
        let z1_p = p.mul(&self.z1).into_affine();

        let worked: bool = if c == 0 {
            let s_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.x);
            let t_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.y);
            (self.c4 == Self::new_other_with_both(&self.z1, &self.z2))
                && (self.c5 == PedersenComm::new_with_both(s_dash, self.z3).comm)
                && (self.c6 == PedersenComm::new_with_both(t_dash, self.z4).comm)
        } else {
            let u_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.x);
            let v_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.y);
            ((self.c4 - self.c1) == Self::new_other_with_both(&self.z1, &self.z2))
                && (self.c7 == PedersenComm::new_with_both(u_dash, self.z3).comm)
                && (self.c8 == PedersenComm::new_with_both(v_dash, self.z4).comm)
        };

        worked && self.eap.verify(transcript)
    }
}
