//! Defines a protocol for EC point scalar multiplication.
//! Namely, this protocol proves that we know S = λP for a known point P and an
//! unknown scalar λ.
//! The particular proof implemented in this file is the same as the proof presented in
//! Construction 4.1 (CDLS).

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};

use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::ops::Mul;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

use crate::{
    ec_point_add_protocol::{
        ECPointAddIntermediate, ECPointAddIntermediateTranscript, ECPointAddProof,
        ECPointAddProofTranscriptable,
    },
    pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig,
    point_add::PointAddProtocol,
    scalar_mul::ScalarMulProtocol,
    transcript::ECScalarMulTranscript,
};

/// ECScalarMulProofTranscriptable. This trait provides a notion of `Transcriptable` which implies that
/// a particular struct can be, in some sense, added to the transcript for a scalar multiplication proof.
pub trait ECScalarMulProofTranscriptable<P: PedersenConfig> {
    /// Affine: the type of affine point used in these protocols. This is set just to allow
    /// other protocols to take advantage of this information.
    type Affine;

    /// add_to_transcript. This function adds all of the underlying proof information to the
    /// `transcript` object. This function is typically called externally when this proof
    /// forms part of a larger proof object.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object.
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    );
}

/// ECScalarMulProof. This struct acts as a container for the Scalar multiplication proof.
/// Essentially, this struct can be used to create new proofs (via ```create```), and verify
/// existing proofs (via ```verify```).
/// In this documentation we use the convention of S = λP, and that each commitment C_i has associated
/// randomness r_i.
pub struct ECScalarMulProof<P: PedersenConfig> {
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

/// ECScalarMulProofIntermediate. This struct acts as a container for all of the intermediate
/// values that are produced during the initial proof creation process (i.e before the challenge is
/// created). This exists to allow easier separation between the creation of the initial, random values
/// and later values.
pub struct ECScalarMulProofIntermediate<P: PedersenConfig> {
    /// alpha: the randomly generated scalar (produced during setup).
    pub alpha: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    /// c4: the commitment to the random value α.
    pub c4: sw::Affine<<P as PedersenConfig>::OCurve>,
    /// r4: the randomness associated with the commitment to α.
    pub r4: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,

    /// c5: the commitment to the x co-ordinate of αP.
    pub c5: PedersenComm<P>,
    /// c6: the commitment to the y co-ordinate of αP.
    pub c6: PedersenComm<P>,
    /// c7: the commitment to the x co-ordinate of (α-λ)P.
    pub c7: PedersenComm<P>,
    /// c8: the commitment to the y co-ordinate of (α-λ)P.
    pub c8: PedersenComm<P>,

    /// eapi: the intermediates for the elliptic curve addition proof.
    pub eapi: ECPointAddIntermediate<P>,
}

/// ECScalarMulProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `ECScalarMulProofIntermediate` except from
/// the randomness values.
pub struct ECScalarMulProofIntermediateTranscript<P: PedersenConfig> {
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

    /// eap: the elliptic curve addition proof intermediate transcript. This proof is used to show that
    /// αP = λP + ((α-λ)P).
    pub eapi: ECPointAddIntermediateTranscript<P>,
}

impl<P: PedersenConfig> ScalarMulProtocol<P> for ECScalarMulProof<P> {
    type Intermediate = ECScalarMulProofIntermediate<P>;
    type IntermediateTranscript = ECScalarMulProofIntermediateTranscript<P>;

    const SUB_ITER: usize = 8;
    const SHIFT_BY: usize = 1;

    /// initialise_transcript. This function accepts a transcript and initialises it to the domain separator state.
    /// This is typically used for generic callers.
    /// # Arguments
    /// * `transcript` - the transcript object.
    fn initialise_transcript(transcript: &mut Transcript) {
        ECScalarMulTranscript::domain_sep(transcript);
    }

    fn challenge_scalar(transcript: &mut Transcript) -> [u8; 64] {
        ECScalarMulTranscript::challenge_scalar(transcript, b"c")
    }

    /// make_intermediate_transcript. This function accept a set of intermediate values (`inter`)
    /// and builds a new ECScalarMulProofIntermediateTranscript from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    fn make_intermediate_transcript(
        inter: ECScalarMulProofIntermediate<P>,
    ) -> ECScalarMulProofIntermediateTranscript<P> {
        ECScalarMulProofIntermediateTranscript {
            c4: inter.c4,
            c5: inter.c5.comm,
            c6: inter.c6.comm,
            c7: inter.c7.comm,
            c8: inter.c8.comm,
            eapi: ECPointAddProof::make_intermediate_transcript(inter.eapi),
        }
    }

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
    fn create_intermediates_with_existing_commitments<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c1: &sw::Affine<P::OCurve>,
        _r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> ECScalarMulProofIntermediate<P> {
        // First we make the unique alpha value. We repeat until we've
        // found the right value. Note that whp we do not expect this loop to repeat
        // many times, as the probability of choosing α ∈ {0, λ, 2λ} is pretty small.
        let mut alpha = <P as PedersenConfig>::get_random_p(rng);

        loop {
            if alpha != Self::OTHER_ZERO && alpha != *lambda && alpha != (*lambda).double() {
                break;
            }
            alpha = <P as PedersenConfig>::get_random_p(rng);
        }

        // Now we compute the co-ordinates of αP.
        // N.B This differs from the paper: to prevent re-using `s` (even across cases)
        // we label the co-ordinates of αP = (apx, apy).
        let ap = ((*p).mul(alpha)).into_affine();
        let apx = <P as PedersenConfig>::from_ob_to_sf(ap.x);
        let apy = <P as PedersenConfig>::from_ob_to_sf(ap.y);

        // Save scalar mult by computing ap - s
        let amlp = (ap - s).into_affine();
        let amlpx = <P as PedersenConfig>::from_ob_to_sf(amlp.x);
        let amlpy = <P as PedersenConfig>::from_ob_to_sf(amlp.y);

        // And now we finally can commit to things.

        // c4 = Comm_{p}(α).
        let (c4, r4) = <P as PedersenConfig>::create_commit_other(&alpha, rng);

        // c5 = Comm_{p}(apx), c6 = Comm_{p}(apy).
        let c5 = PedersenComm::new(apx, rng);
        let c6 = PedersenComm::new(apy, rng);

        // c7 = Comm_{q}(amlx), c8 = Comm_{q}(amly).
        let c7 = PedersenComm::new(amlpx, rng);
        let c8 = PedersenComm::new(amlpy, rng);

        // Part 2: make the transcript and the proof itself.
        Self::make_transcript(
            transcript, c1, &c2.comm, &c3.comm, &c4, &c5.comm, &c6.comm, &c7.comm, &c8.comm,
        );

        // Now make the EC point addition intermediates.
        let eapi = ECPointAddProof::create_intermediates_with_existing_commitments(
            transcript, rng, *s, amlp, ap, c2, c3, &c7, &c8, &c5, &c6,
        );

        // Now return the intermediates.
        ECScalarMulProofIntermediate {
            alpha,
            c4,
            r4,
            c5,
            c6,
            c7,
            c8,
            eapi,
        }
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize {
        self.c4.compressed_size()
            + self.c5.compressed_size()
            + self.c6.compressed_size()
            + self.c7.compressed_size()
            + self.c8.compressed_size()
            + self.z1.compressed_size()
            + self.z2.compressed_size()
            + self.z3.compressed_size()
            + self.z4.compressed_size()
            + self.eap.serialized_size()
    }

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
    ) -> Self {
        Self::create_proof_with_challenge(
            s,
            lambda,
            p,
            inter,
            c1,
            r1,
            c2,
            c3,
            &<P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1),
        )
    }

    /// create_proof_with_challenge_byte. This function returns a proof that s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve. Notably, this function uses a pre-supplied challenge (`chal`) as the challenge value.    
    /// # Arguments
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `chal` - the challenge byte.
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
    ) -> Self {
        let bit = chal & 1;
        // Use that to make a challenge.
        let challenge = <P as PedersenConfig>::make_single_bit_challenge(bit);
        Self::create_proof_with_challenge(s, lambda, p, inter, c1, r1, c2, c3, &challenge)
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
    ) -> bool {
        // We just make the challenge and call into the more general routine.
        self.verify_with_challenge(
            p,
            &<P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1),
            c1,
            c2,
            c3,
        )
    }

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
    ) -> bool {
        let bit = chal & 1;
        // Use that to make a challenge.
        let challenge = <P as PedersenConfig>::make_single_bit_challenge(bit);
        self.verify_with_challenge(p, &challenge, c1, c2, c3)
    }

    /// add_proof_to_transcript. This function acts as an alias for the add_to_transcript function that may
    /// be realised by other means.
    fn add_proof_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        self.add_to_transcript(transcript, c1, c2, c3);
    }
}

impl<P: PedersenConfig> ECScalarMulProof<P> {
    /// OTHER_ZERO. This constant is used to act as the zero element for the ScalarField of
    /// OCurve. This is here primarily because the proof formation needs it when choosing α.
    const OTHER_ZERO: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField =
        <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField::ZERO;

    /// create_proof_with_challenge. This function returns a proof that s = λp for some publicly known point `P`.
    /// Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve. Notably, this function uses a pre-supplied challenge (`chal`) as the challenge value.    
    /// # Arguments
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `chal` - the challenge.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proof_with_challenge(
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ECScalarMulProofIntermediate<P>,
        _c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        // Because we've already generated the randomness, we now extract those values to use
        // in our challenges.
        let beta_1 = inter.r4;
        let beta_2 = inter.c5.r;
        let beta_3 = inter.c6.r;
        let beta_4 = inter.c7.r;
        let beta_5 = inter.c8.r;

        // Now we compute the co-ordinates of αP.
        // Note that, unlike in other functions, we only need the points themselves (i.e
        // we do not need to separately label the co-ordinates).
        let ap = ((*p).mul(inter.alpha)).into_affine();

        // We now do the same with (α-λ)P. We label (α-λ)P = amlp as before.
        let amlp = ((*p).mul(inter.alpha - lambda)).into_affine();

        // Prove that αP = λP + ((α-λ)P) using our existing commitments and challenge.
        let eap = ECPointAddProof::create_proof_with_challenge(
            *s,
            amlp,
            ap,
            &inter.eapi,
            c2,
            c3,
            &inter.c7,
            &inter.c8,
            &inter.c5,
            &inter.c6,
            chal,
        );

        // And, finally, construct the proof.
        // Note that c can only be 0 or 1 here.
        if (*chal) == <P as PedersenConfig>::CM1 {
            Self {
                c4: inter.c4,
                c5: inter.c5.comm,
                c6: inter.c6.comm,
                c7: inter.c7.comm,
                c8: inter.c8.comm,
                z1: inter.alpha,
                z2: beta_1,
                z3: beta_2,
                z4: beta_3,
                eap,
            }
        } else {
            Self {
                c4: inter.c4,
                c5: inter.c5.comm,
                c6: inter.c6.comm,
                c7: inter.c7.comm,
                c8: inter.c8.comm,
                z1: inter.alpha - *lambda,
                z2: beta_1 - r1,
                z3: beta_4,
                z4: beta_5,
                eap,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// make_transcript. This function accepts a `transcript`, alongside all auxiliary commitments (`c1`,..., `c8`)
    /// and incorporates each commitment into the transcript.
    /// # Arguments
    /// * `transcript` - the transcript object to which the commitments are added.
    /// * `ci` - the commitments. These are detailed in the ECScalarMulProof struct documentation.
    pub fn make_transcript(
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

    /// make_subproof_transcript. This function adds the subproof object to the transcript.
    /// The subproof object must be an ECPointAddProofTranscriptable object.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `ep` - the sub-proof object.
    #[allow(clippy::too_many_arguments)]
    pub fn make_subproof_transcript<EP: ECPointAddProofTranscriptable<P>>(
        transcript: &mut Transcript,
        ep: &EP,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        ep.add_to_transcript(transcript, c1, c2, c3, c4, c5, c6);
    }

    /// verify_with_challenge. This function returns true if the proof held by `self` is valid and false otherwise.
    /// In other words, this function returns true if the proof object is a valid proof of scalar multiplication.
    /// Notably, this function uses a pre-determined binary challenge (`chal`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `p` - the publicly known point.
    /// * `chal` - the challenge.
    pub fn verify_with_challenge(
        &self,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        chal: &<P as CurveConfig>::ScalarField,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool {
        // z1_p = z1P, which is used in both verifier computations.
        let z1_p = p.mul(&self.z1).into_affine();
        // The challenge must be binary.
        assert!(*chal == <P as PedersenConfig>::CM1 || *chal == <P as PedersenConfig>::CP1);

        let worked: bool = if *chal == <P as PedersenConfig>::CM1 {
            let s_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.x);
            let t_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.y);
            (self.c4 == <P as PedersenConfig>::new_other_with_both(&self.z1, &self.z2))
                && (self.c5 == PedersenComm::new_with_both(s_dash, self.z3).comm)
                && (self.c6 == PedersenComm::new_with_both(t_dash, self.z4).comm)
        } else {
            let u_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.x);
            let v_dash = <P as PedersenConfig>::from_ob_to_sf(z1_p.y);
            ((self.c4 - c1) == <P as PedersenConfig>::new_other_with_both(&self.z1, &self.z2))
                && (self.c7 == PedersenComm::new_with_both(u_dash, self.z3).comm)
                && (self.c8 == PedersenComm::new_with_both(v_dash, self.z4).comm)
        };

        worked
            && self
                .eap
                .verify_with_challenge(c2, c3, &self.c7, &self.c8, &self.c5, &self.c6, chal)
    }
}

impl<P: PedersenConfig> ECScalarMulProofTranscriptable<P> for ECScalarMulProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        ECScalarMulProof::make_transcript(
            transcript, c1, c2, c3, &self.c4, &self.c5, &self.c6, &self.c7, &self.c8,
        );
        ECScalarMulProof::make_subproof_transcript(
            transcript, &self.eap, c2, c3, &self.c7, &self.c8, &self.c5, &self.c6,
        );
    }
}

impl<P: PedersenConfig> ECScalarMulProofTranscriptable<P> for ECScalarMulProofIntermediate<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        ECScalarMulProof::make_transcript(
            transcript,
            c1,
            c2,
            c3,
            &self.c4,
            &self.c5.comm,
            &self.c6.comm,
            &self.c7.comm,
            &self.c8.comm,
        );
        ECScalarMulProof::make_subproof_transcript(
            transcript,
            &self.eapi,
            c2,
            c3,
            &self.c7.comm,
            &self.c8.comm,
            &self.c5.comm,
            &self.c6.comm,
        );
    }
}

impl<P: PedersenConfig> ECScalarMulProofTranscriptable<P>
    for ECScalarMulProofIntermediateTranscript<P>
{
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        ECScalarMulProof::make_transcript(
            transcript, c1, c2, c3, &self.c4, &self.c5, &self.c6, &self.c7, &self.c8,
        );
        ECScalarMulProof::<P>::make_subproof_transcript(
            transcript, &self.eapi, c2, c3, &self.c7, &self.c8, &self.c5, &self.c6,
        );
    }
}
