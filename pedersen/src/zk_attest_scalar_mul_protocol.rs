//! This protocol realises the ZKAttest scalar multiplication protocol.
//! Namely, this protocol proves that we know S = λP for a known point P and an
//! unknown scalar λ.
//! Please note that this implementation does not match the ZKAttest implementation.

use ark_ec::{
    short_weierstrass::{self as sw},
    CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_serialize::CanonicalSerialize;
use ark_std::ops::Mul;
use rand::{CryptoRng, RngCore};

use crate::{
    pedersen_config::{PedersenComm, PedersenConfig},
    point_add::PointAddProtocol,
    scalar_mul::ScalarMulProtocol,
    transcript::ZKAttestECScalarMulTranscript,
    zk_attest_point_add_protocol::{
        ZKAttestPointAddProof, ZKAttestPointAddProofIntermediate,
        ZKAttestPointAddProofIntermediateTranscript, ZKAttestPointAddProofTranscriptable,
    },
};

/// ZKAttestECScalarMulTranscriptable. This trait provides a notion of `Transcriptable`, which
/// implies that the particular struct can be, in some sense, added to the transcript for a ZK-Attest style
/// scalar multiplication proof.
pub trait ZKAttestECScalarMulTranscriptable<P: PedersenConfig> {
    /// Affine. This type is the type of Pedersen commitment used in this protocol.
    /// This is primarily defined to make sub-layers more composable.
    type Affine;

    /// add_to_transcript. This function adds `self` to the transcript object.
    /// This should typically be used before creating a challenge (either for proving
    /// or verification).
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    );
}

/// ZKAttestECScalarMulProof. This struct acts as a container for the ZKAttest Scalar
/// multiplication proof. You can use this struct to create new proofs (using ```create```)
/// and verify their correctness with ```verify```.
/// In this documentation we use the convention of S = λP.
pub struct ZKAttestECScalarMulProof<P: PedersenConfig> {
    /// alpha: the randomly generated value used during the proof.
    pub alpha: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,

    /// a1: the commitment to αg.    
    pub a1: sw::Affine<<P as PedersenConfig>::OCurve>,

    /// a2: The commitment to αg.x
    pub a2: sw::Affine<P>,

    /// a3: The commitment to αg.y.
    pub a3: sw::Affine<P>,

    /// c4: The commitment to (α-λ)g.x.
    pub c4: sw::Affine<P>,

    /// c5: The commitment to (α-λ)g.y.
    pub c5: sw::Affine<P>,

    /// z1: the first part of the challenge.
    pub z1: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    /// z2: the second part of the challenge.
    pub z2: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
    /// z3: the third part of the challenge.
    pub z3: <P as CurveConfig>::ScalarField,
    /// z4: the fourth part of the challenge.
    pub z4: <P as CurveConfig>::ScalarField,

    /// pi: the point addition proof. This is optionally set iff the
    /// second challenge is 1. Otherwise, the pii is set.
    pub pi: Option<ZKAttestPointAddProof<P>>,
    pub pii: Option<ZKAttestPointAddProofIntermediateTranscript<P>>,
}

/// ZKAttestECScalarMulProofIntermediate. This struct acts as a container for the
/// intermediate values produced during the setup stage of the proof. This struct
/// should typically only be used when the transcript needs to be further modified
/// before a challenge is created.
pub struct ZKAttestECScalarMulProofIntermediate<P: PedersenConfig> {
    /// alpha: the randomly generated value.
    pub alpha: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,

    /// a1: the commitment to α.
    pub a1: sw::Affine<<P as PedersenConfig>::OCurve>,
    /// beta_1: the randomness value for the commitment to a1 (α).
    pub beta_1: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,

    /// a2: the commitment to (α.x)
    pub a2: PedersenComm<P>,
    /// a3: the commitment to (α.y)
    pub a3: PedersenComm<P>,

    /// c4: the commitment to (α-λ)g.x.
    pub c4: PedersenComm<P>,

    /// c5: the commitment to (α-λ)g.y.
    pub c5: PedersenComm<P>,

    /// pi: the intermediate values for the point addition proof. Note that
    /// this value is later converted either into a transcript for a point addition
    /// proof or to an actual point addition proof (depending on the challenge).
    pub pi: ZKAttestPointAddProofIntermediate<P>,
}

/// ZKAttestECScalarMulProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `ZKAttestECScalarMulProofIntermediate` except from
/// the randomness values.
pub struct ZKAttestECScalarMulProofIntermediateTranscript<P: PedersenConfig> {
    /// alpha: the randomly generated value used during the proof.
    pub alpha: <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,

    /// a1: the commitment to αg.    
    pub a1: sw::Affine<<P as PedersenConfig>::OCurve>,

    /// a2: The commitment to αg.x
    pub a2: sw::Affine<P>,

    /// a3: The commitment to αg.y.
    pub a3: sw::Affine<P>,

    /// c4: The commitment to (α-λ)g.x.
    pub c4: sw::Affine<P>,

    /// c5: The commitment to (α-λ)g.y.
    pub c5: sw::Affine<P>,

    /// pi: the point addition proof transcriptable. This is essentially
    /// just here to add relevant sub-information to the transcript.
    pub pi: ZKAttestPointAddProofIntermediateTranscript<P>,
}

impl<P: PedersenConfig> ScalarMulProtocol<P> for ZKAttestECScalarMulProof<P> {
    type Intermediate = ZKAttestECScalarMulProofIntermediate<P>;
    type IntermediateTranscript = ZKAttestECScalarMulProofIntermediateTranscript<P>;

    const SUB_ITER: usize = 4;
    const SHIFT_BY: usize = 2;

    /// initialise_transcript. This function accepts a transcript and initialises it to the domain separator state.
    /// This is typically used for generic callers.
    /// # Arguments
    /// * `transcript` - the transcript object.
    fn initialise_transcript(transcript: &mut Transcript) {
        transcript.domain_sep();
    }

    fn challenge_scalar(transcript: &mut Transcript) -> [u8; 64] {
        transcript.challenge_scalar(b"c")
    }

    /// make_intermediate_transcript. This function accepts a set of intermediates (`inter`) and builds
    /// a new intermediate transcript object from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate objects.
    fn make_intermediate_transcript(
        inter: ZKAttestECScalarMulProofIntermediate<P>,
    ) -> ZKAttestECScalarMulProofIntermediateTranscript<P> {
        ZKAttestECScalarMulProofIntermediateTranscript {
            alpha: inter.alpha,
            a1: inter.a1,
            a2: inter.a2.comm,
            a3: inter.a3.comm,
            c4: inter.c4.comm,
            c5: inter.c5.comm,
            pi: ZKAttestPointAddProof::make_intermediate_transcript(inter.pi),
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
    ) -> ZKAttestECScalarMulProofIntermediate<P> {
        // First we make the unique alpha value. Note that ZKAttest places no restriction on the
        // value of alpha.
        let alpha = <P as PedersenConfig>::get_random_p(rng);
        let (a1, beta_1) = <P as PedersenConfig>::create_commit_other(&alpha, rng);

        // Now we compute the gamma values.
        let gamma = ((*p).mul(alpha)).into_affine();
        let a2 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(gamma.x), rng);
        let a3 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(gamma.y), rng);

        // And now the other one.
        let amlp = ((*p).mul(alpha - lambda)).into_affine();
        let c4 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(amlp.x), rng);
        let c5 = PedersenComm::new(<P as PedersenConfig>::from_ob_to_sf(amlp.y), rng);

        Self::make_transcript(
            transcript, c1, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &a1, &a2.comm, &a3.comm,
        );

        let pi = ZKAttestPointAddProof::create_intermediates_with_existing_commitments(
            transcript, rng, amlp, *s, gamma, &c4, &c5, c2, c3, &a2, &a3,
        );

        ZKAttestECScalarMulProofIntermediate {
            alpha,
            a1,
            beta_1,
            a2,
            a3,
            c4,
            c5,
            pi,
        }
    }

    /// create_proof. This function creates a proof that
    /// s = λp for some publicly known point `P`. Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve. Note that this function uses challenges derived from `chal_buf`.
    /// # Arguments
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `inter` - the intermediate values.
    /// * `chal_buf` - the buffer from which challenges are produced.
    fn create_proof(
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ZKAttestECScalarMulProofIntermediate<P>,
        chal_buf: &[u8],
        c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self {
        let chal0 = &<P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1);
        let chal1 =
            &<P as PedersenConfig>::make_single_bit_challenge((chal_buf.last().unwrap() & 2) >> 1);
        Self::create_proof_with_challenge(s, lambda, p, inter, chal0, chal1, c1, r1, c2, c3)
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
        let chal0 = <P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1);
        let chal1 =
            <P as PedersenConfig>::make_single_bit_challenge((chal_buf.last().unwrap() & 2) >> 1);
        self.verify_with_challenge(p, &chal0, &chal1, c1, c2, c3)
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize {
        let lhs = self.alpha.compressed_size()
            + self.a1.compressed_size()
            + self.a2.compressed_size()
            + self.a3.compressed_size()
            + self.c4.compressed_size()
            + self.c5.compressed_size()
            + self.z1.compressed_size()
            + self.z2.compressed_size()
            + self.z3.compressed_size()
            + self.z4.compressed_size();

        if let Some(proof) = &self.pi {
            lhs + proof.serialized_size()
        } else if let Some(pii) = &self.pii {
            lhs + pii.serialized_size()
        } else {
            panic!("Cannot have both proof and pii not set!");
        }
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
        let chal0 = <P as PedersenConfig>::make_single_bit_challenge(chal & 1);
        let chal1 = <P as PedersenConfig>::make_single_bit_challenge((chal & 2) >> 1);
        Self::create_proof_with_challenge(s, lambda, p, inter, &chal0, &chal1, c1, r1, c2, c3)
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
        let chal0 = <P as PedersenConfig>::make_single_bit_challenge(chal & 1);
        let chal1 = <P as PedersenConfig>::make_single_bit_challenge((chal & 2) >> 1);
        self.verify_with_challenge(p, &chal0, &chal1, c1, c2, c3)
    }

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
    ) {
        self.add_to_transcript(transcript, c1, c2, c3);
    }
}

impl<P: PedersenConfig> ZKAttestECScalarMulProof<P> {
    /// make_transcript. This function adds all of the relevant sub-commitments
    /// to the transcript for the scalar multiplication proof.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `ci` - the commitments (over the T curve) for the point co-ordinates.
    /// * `ai` - the commitments for the intermediate proof values.
    #[allow(clippy::too_many_arguments)]
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<<P as PedersenConfig>::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        a1: &sw::Affine<<P as PedersenConfig>::OCurve>,
        a2: &sw::Affine<P>,
        a3: &sw::Affine<P>,
    ) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        transcript.domain_sep();
        let mut compressed_bytes = Vec::new();

        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C3", &compressed_bytes[..]);

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"C5", &compressed_bytes[..]);

        a1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"A1", &compressed_bytes[..]);

        a2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"A2", &compressed_bytes[..]);

        a3.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_point(b"A3", &compressed_bytes[..]);
    }

    /// create_proof_with_challenge. This function creates a proof that
    /// s = λp for some publicly known point `P`. Note that `s` and `p` are both members of P::OCurve, and not the
    /// associated T Curve. Note that this function uses challenges` c0` and `c1`, as used in ZKAttest.
    /// # Arguments
    /// * `s` - the secret, target point.
    /// * `lambda` - the scalar multiple that is used.
    /// * `p` - the publicly known generator.
    /// * `inter` - the intermediate values.
    /// * `chal0` - the c0 challenge. If chal0 corresponds to 0, no point addition proof is made. If chal0 corresponds to 1,
    ///   then the point addition proof is invoked with chal1.
    /// * `chal1` - the c1 challenge. This is only used if chal1 == 1.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proof_with_challenge(
        s: &sw::Affine<<P as PedersenConfig>::OCurve>,
        lambda: &<<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ZKAttestECScalarMulProofIntermediate<P>,
        chal0: &<P as CurveConfig>::ScalarField,
        chal1: &<P as CurveConfig>::ScalarField,
        _c1: &sw::Affine<P::OCurve>,
        r1: &<P::OCurve as CurveConfig>::ScalarField,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
    ) -> Self {
        // The challenges must be mapped to either 0 or 1.
        assert!(*chal0 == <P as PedersenConfig>::CM1 || *chal0 == <P as PedersenConfig>::CP1);
        assert!(*chal1 == <P as PedersenConfig>::CM1 || *chal1 == <P as PedersenConfig>::CP1);

        // Now we rebuild the parts we need for the protocol. N.B
        // the code below creates the transcriptable object differently
        // depending on the challenge chal0. Notably, both objects are transcriptable.
        let gamma = ((*p).mul(inter.alpha)).into_affine();
        let amlp = ((*p).mul(inter.alpha - lambda)).into_affine();
        let (pi, pii) = if *chal0 == <P as PedersenConfig>::CP1 {
            (
                Some(ZKAttestPointAddProof::create_proof_with_challenge(
                    amlp, *s, gamma, &inter.pi, &inter.c4, &inter.c5, c2, c3, &inter.a2, &inter.a3,
                    chal1,
                )),
                None,
            )
        } else {
            (
                None,
                Some(ZKAttestPointAddProof::make_intermediate_transcript(
                    inter.pi,
                )),
            )
        };

        // Now we chose the z1,z2,z3 and z4.
        let (z1, z2, z3, z4) = if *chal0 == <P as PedersenConfig>::CP1 {
            // If chal0 == 1 then we return z1 = alpha - lambda, z2 = beta_1 - r1, z3 = beta_4 and z4 = beta_5.
            // Note that beta_4 = c4.r and beta_5 = c5.r
            (
                inter.alpha - lambda,
                inter.beta_1 - r1,
                inter.c4.r,
                inter.c5.r,
            )
        } else {
            // If chal0 == 0 then we return z1 = alpha, z2 = beta_1, z3 = beta_2, z4 = beta_3.
            // Note that beta_2 = a2.r and beta_3 = a3.r
            (inter.alpha, inter.beta_1, inter.a2.r, inter.a3.r)
        };

        // And now return the proof.
        Self {
            alpha: inter.alpha,
            a1: inter.a1,
            a2: inter.a2.comm,
            a3: inter.a3.comm,
            c4: inter.c4.comm,
            c5: inter.c5.comm,
            z1,
            z2,
            z3,
            z4,
            pi,
            pii,
        }
    }

    /// make_subproof_transcript. This function adds the (potential) ZKAttest point addition proof `pi`
    /// to the transcript object. Note that `pi` must be a transcriptable type for a ZKAttest point addition proof.
    /// # Arguments
    /// * `pi` - the proof object.
    /// * `transcript` - the transcript object.
    /// * `ci` - the commitments for the point addition protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn make_subproof_transcript<
        PT: ZKAttestPointAddProofTranscriptable<P, Affine = sw::Affine<P>>,
    >(
        pi: &PT,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        pi.add_to_transcript(transcript, c1, c2, c3, c4, c5, c6);
    }

    /// verify_with_challenge.
    /// This function verifies the proof held in `self`, returning true if the proof is valid (and false otherwise).
    /// Notably, this function uses the challenges `chal0` and `chal`.
    /// # Arguments
    /// * `self` - the proof object.    
    /// * `p` - the publicly known point.
    /// * `chal0` - the chal0 challenge.
    /// * `chal1` - the chal1 challenge.
    pub fn verify_with_challenge(
        &self,
        p: &sw::Affine<<P as PedersenConfig>::OCurve>,
        chal0: &<P as CurveConfig>::ScalarField,
        chal1: &<P as CurveConfig>::ScalarField,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) -> bool {
        // chal0 must be mapped to either 0 or 1.
        assert!(*chal0 == <P as PedersenConfig>::CM1 || *chal0 == <P as PedersenConfig>::CP1);
        // chal1 must also be mapped to either 0 or 1.
        assert!(*chal1 == <P as PedersenConfig>::CM1 || *chal1 == <P as PedersenConfig>::CP1);

        // In either case we need z1P.
        // NOTE: this must be an affine point.
        let t = (*p).mul(self.z1).into_affine();

        // We also always check that the commitments to a1 passes.
        let (a1c, _a1r) = <P as PedersenConfig>::create_commit_other_with_both(&self.z1, &self.z2);
        let first = if *chal0 == <P as PedersenConfig>::CP1 {
            self.a1 == a1c + c1
        } else {
            self.a1 == a1c
        };

        // Now the others. If *chal0 == 0, then we just check the other commitments.
        // N.B This block here just handles the fact that in both cases we have to check
        // something against Com(t1, z3) and Com(t2, z4).
        let (lhs1, lhs2) = if *chal0 == <P as PedersenConfig>::CM1 {
            (self.a2, self.a3)
        } else {
            (self.c4, self.c5)
        };

        // Now check the addition proof, if it's been set.
        let worked: bool;

        // One or the other of these must be set.
        assert!(self.pii.is_none() ^ self.pi.is_none());

        if let Some(proof) = &self.pi {
            // This can only happen if chal0 == 1.
            assert!(*chal0 == <P as PedersenConfig>::CP1);
            worked =
                proof.verify_with_challenge(&self.c4, &self.c5, c2, c3, &self.a2, &self.a3, chal1);
        } else {
            // This can only happen if chal0 = 0.
            assert!(*chal0 == <P as PedersenConfig>::CM1);
            worked = true;
        }

        // And, finally, check all sub-portions.
        first
            && worked
            && (lhs1
                == PedersenComm::new_with_both(<P as PedersenConfig>::from_ob_to_sf(t.x), self.z3)
                    .comm)
            && (lhs2
                == PedersenComm::new_with_both(<P as PedersenConfig>::from_ob_to_sf(t.y), self.z4)
                    .comm)
    }
}

impl<P: PedersenConfig> ZKAttestECScalarMulTranscriptable<P> for ZKAttestECScalarMulProof<P> {
    type Affine = sw::Affine<P>;

    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        // Make the regular transcript.
        ZKAttestECScalarMulProof::make_transcript(
            transcript, c1, c2, c3, &self.c4, &self.c5, &self.a1, &self.a2, &self.a3,
        );
        // Make the sub-transcripts, too.
        // Only one of these can reasonably be set.
        assert!(self.pi.is_none() ^ self.pii.is_none());
        if let Some(pi) = &self.pi {
            ZKAttestECScalarMulProof::make_subproof_transcript(
                pi, transcript, &self.c4, &self.c5, c2, c3, &self.a2, &self.a3,
            );
        }

        if let Some(pii) = &self.pii {
            ZKAttestECScalarMulProof::make_subproof_transcript(
                pii, transcript, &self.c4, &self.c5, c2, c3, &self.a2, &self.a3,
            );
        }
    }
}

impl<P: PedersenConfig> ZKAttestECScalarMulTranscriptable<P>
    for ZKAttestECScalarMulProofIntermediate<P>
{
    type Affine = sw::Affine<P>;

    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        // Make the regular transcript.
        ZKAttestECScalarMulProof::make_transcript(
            transcript,
            c1,
            c2,
            c3,
            &self.c4.comm,
            &self.c5.comm,
            &self.a1,
            &self.a2.comm,
            &self.a3.comm,
        );
        // Make the sub-transcripts, too.
        ZKAttestECScalarMulProof::make_subproof_transcript(
            &self.pi,
            transcript,
            &self.c4.comm,
            &self.c5.comm,
            c2,
            c3,
            &self.a2.comm,
            &self.a3.comm,
        );
    }
}

impl<P: PedersenConfig> ZKAttestECScalarMulTranscriptable<P>
    for ZKAttestECScalarMulProofIntermediateTranscript<P>
{
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P::OCurve>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
    ) {
        // Make the regular transcript.
        ZKAttestECScalarMulProof::make_transcript(
            transcript, c1, c2, c3, &self.c4, &self.c5, &self.a1, &self.a2, &self.a3,
        );

        // Make the sub-transcripts, too.
        ZKAttestECScalarMulProof::make_subproof_transcript(
            &self.pi, transcript, &self.c4, &self.c5, c2, c3, &self.a2, &self.a3,
        );
    }
}
