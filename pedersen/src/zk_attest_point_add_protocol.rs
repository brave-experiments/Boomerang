//! Defines a point addition protocol using ZKAttest's proof of point addition.
//! Namely, this protocol proves that `t = a + b` for two elliptic curve points `a`, `b`.
//! Note that this particular implementation is defined in the same way as the ZKAttest implementation, and not as per the ZKAttest paper.
//! From this perspective, this implementation can be viewed as a transcribed variant of the code found here:
//! https://github.com/cloudflare/zkp-ecdsa/blob/07a71c9dfffe0b8a9ab3c92d7f97d72a0af7b78a/src/exp/pointAdd.ts#L92.

use ark_ec::{
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_ff::fields::Field;
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};

use crate::{
    equality_protocol::{
        EqualityProof, EqualityProofIntermediate, EqualityProofIntermediateTranscript,
        EqualityProofTranscriptable,
    },
    mul_protocol::{
        MulProof, MulProofIntermediate, MulProofIntermediateTranscript, MulProofTranscriptable,
    },
    pedersen_config::{PedersenComm, PedersenConfig},
    point_add::PointAddProtocol,
    transcript::ZKAttestECPointAdditionTranscript,
};

/// ZKAttestPointAddProofTranscriptable. This trait provides a notion of `Transcriptable`, which
/// implies that the particular struct can be, in some sense, added to the transcript for a ZK-Attest style
/// point addition proof.
pub trait ZKAttestPointAddProofTranscriptable<P: PedersenConfig> {
    /// Affine: the type of affine point used inside these proofs. This is defined to
    /// ensure consistency for higher-level protocols.
    type Affine;
    /// add_to_transcript. This function adds all of the underlying information for this proof to the
    /// transcript. This is carried out to allow a proper challenge to be computed later on.
    /// # Arguments
    /// *`self` - the proof object.
    /// *`transcript` - the transcript object that is used.
    /// * `ci` - the commitments to the co-ordinates.
    #[allow(clippy::too_many_arguments)]
    fn add_to_transcript(
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

/// ZKAttestPointAddProof. This struct acts as a container for the ZKAttest Point addition proof.
/// New proof objects can be made via the `create` function, whereas existing
/// proofs may be verified via the `verify` function.
/// Note that this struct's documentation uses the convention that we are proving `t = a + b`.
pub struct ZKAttestPointAddProof<P: PedersenConfig> {
    /* Note: these are kept here just so the naming convention is easier to understand.
    /// c1: the commitment to a.x.
    pub c1: sw::Affine<P>,
    /// c2: the commitment to a.y.
    pub c2: sw::Affine<P>,
    /// c3: the commitment to b.x.
    pub c3: sw::Affine<P>,
    /// c4: the commitment to b.y.
    pub c4: sw::Affine<P>,
    /// c5: the commitment to t.x.
    pub c5: sw::Affine<P>,
    /// c6: the commitment to t.y.
    pub c6: sw::Affine<P>,
    */
    // Note: this is only placed here to explain the naming convention.
    // This is to make the documentation here easier to compare to
    // the original ZKAttest Paper.
    // We do not need to store this proof separately, as PedersenCommitments
    // are additively homomorphic.

    // c7: the commitment to b.x - a.x. We compute this as c3 - c1.
    //pub c7 : sw::Affine<P>,
    /// c8: the commitment to (b.x - a.x)^-1
    pub c8: sw::Affine<P>,

    // c9: the commitment to b.y - a.y. We compute this as c4 - c2.
    // pub c9 : sw::Affine<P>
    /// c10: the commitment to (b.y - a.y) / (b.x - a.x).
    pub c10: sw::Affine<P>,

    /// c11: the commitment to ((b.y - a.y) / (b.x - a.x))^2
    pub c11: sw::Affine<P>,

    // c12: the commitment to b.x - t.x. We compute this as c3 - c5.
    // pub c12: sw::Affine<P>,
    /// c13: the commitment to (b.y - a.y)/(b.x-a.x) *
    /// (a.x-t.x)
    pub c13: sw::Affine<P>,

    /// mp1: the multiplication proof for showing that c8*c7 = Com(1).
    /// Alternatively, mp1 shows that c7 has an inverse.
    pub mp1: MulProof<P>,

    /// mp2: the multiplication proof for showing that c10 is a commitment
    /// to c9 * c8.
    pub mp2: MulProof<P>,

    /// mp3: the multiplication proof for showing that c11 is a commitment to c10*c10.
    pub mp3: MulProof<P>,
    /// mp4: the multiplication proof for showing that c13 is a commitment to c10*c12.
    pub mp4: MulProof<P>,

    /// e1: the equality proof for showing that c5 + c1 + c3 and c11 are commitments to the same value.
    pub e1: EqualityProof<P>,
    /// e2: the equality proof for showing that c6 + c2 and c13 are commitments to the same value.
    pub e2: EqualityProof<P>,
}

/// ZKAttestPointAddProofIntermediate. This struct acts as a temporary container for the intermediate
/// values produced during setup. This struct should only be used when there are potentially future
/// changes to the transcript object before the challenge can be generated.
pub struct ZKAttestPointAddProofIntermediate<P: PedersenConfig> {
    /* Note: these are only kept here so the naming convention is easier to understand.
    /// c1: the commitment to a.x.
    pub c1: PedersenComm<P>,
    /// c2: the commitment to a.y.
    pub c2: PedersenComm<P>,
    /// c3: the commitment to b.x.
    pub c3: PedersenComm<P>,
    /// c4: the commitment to b.y.
    pub c4: PedersenComm<P>,
    /// c5: the commitment to t.x.
    pub c5: PedersenComm<P>,
    /// c6: the commitment to t.y.
    pub c6: PedersenComm<P>,
    */
    // Note: this is only placed here to explain the naming convention.
    // This is to make the documentation here easier to compare to
    // the original ZKAttest Paper.
    // We do not need to store this proof separately, as PedersenCommitments
    // are additively homomorphic.

    // c7: the commitment to b.x - a.x. We compute this as c3 - c1.
    //pub c7 : PedersenComm<P>,
    /// c8: the commitment to (b.x - a.x)^-1
    pub c8: PedersenComm<P>,

    // c9: the commitment to b.y - a.y. We compute this as c4 - c2.
    // pub c9 : PedersenComm<P>
    /// c10: the commitment to (b.y - a.y) / (b.x - a.x).
    pub c10: PedersenComm<P>,

    /// c11: the commitment to ((b.y - a.y) / (b.x - a.x))^2
    pub c11: PedersenComm<P>,

    // c12: the commitment to b.x - t.x. We compute this as c3 - c5.
    // pub c12: PedersenComm<P>,
    /// c13: the commitment to (b.y - a.y)/(b.x-a.x) *
    /// (a.x-t.x)
    pub c13: PedersenComm<P>,

    /// mpi1: the multiplication proof's intermediates for showing that c8*c7 = Com(1).
    /// Alternatively, mp1 shows that c7 has an inverse.
    pub mpi1: MulProofIntermediate<P>,

    /// mpi2: the multiplication proof's intermediates for showing that c10 is a commitment
    /// to c9 * c8.
    pub mpi2: MulProofIntermediate<P>,

    /// mpi3: the multiplication proof's intermediates for showing that c11 is a commitment to c10*c10.
    pub mpi3: MulProofIntermediate<P>,
    /// mpi4: the multiplication proof's intermediates for showing that c13 is a commitment to c10*c12.
    pub mpi4: MulProofIntermediate<P>,

    /// ei1: the equality proof's intermediates for showing that c5 + c1 + c3 and c11 are commitments to the same value.
    pub ei1: EqualityProofIntermediate<P>,
    /// ei2: the equality proof's intermediates for showing that c6 + c2 and c13 are commitments to the same value.
    pub ei2: EqualityProofIntermediate<P>,
}

impl<P: PedersenConfig> Copy for ZKAttestPointAddProofIntermediate<P> {}
impl<P: PedersenConfig> Clone for ZKAttestPointAddProofIntermediate<P> {
    fn clone(&self) -> Self {
        *self
    }
}

/// ZKAttestPointAddProofIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `ZKAttestPointAddProofIntermediate` except from
/// the randomness values.
pub struct ZKAttestPointAddProofIntermediateTranscript<P: PedersenConfig> {
    /* Again, these are only here for the sake of naming.
    /// c1: the commitment to a.x.
    pub c1: sw::Affine<P>,
    /// c2: the commitment to a.y.
    pub c2: sw::Affine<P>,
    /// c3: the commitment to b.x.
    pub c3: sw::Affine<P>,
    /// c4: the commitment to b.y.
    pub c4: sw::Affine<P>,
    /// c5: the commitment to t.x.
    pub c5: sw::Affine<P>,
    /// c6: the commitment to t.y.
    pub c6: sw::Affine<P>,
    */
    // Note: this is only placed here to explain the naming convention.
    // This is to make the documentation here easier to compare to
    // the original ZKAttest Paper.
    // We do not need to store this proof separately, as PedersenCommitments
    // are additively homomorphic.

    // c7: the commitment to b.x - a.x. We compute this as c3 - c1.
    //pub c7 : sw::Affine<P>,
    /// c8: the commitment to (b.x - a.x)^-1
    pub c8: sw::Affine<P>,

    // c9: the commitment to b.y - a.y. We compute this as c4 - c2.
    // pub c9 : sw::Affine<P>
    /// c10: the commitment to (b.y - a.y) / (b.x - a.x).
    pub c10: sw::Affine<P>,

    /// c11: the commitment to ((b.y - a.y) / (b.x - a.x))^2
    pub c11: sw::Affine<P>,

    // c12: the commitment to b.x - t.x. We compute this as c3 - c5.
    // pub c12: sw::Affine<P>,
    /// c13: the commitment to (b.y - a.y)/(b.x-a.x) *
    /// (a.x-t.x)
    pub c13: sw::Affine<P>,

    /// mp1: the values produced during the multiplication proof for showing that c8*c7 = Com(1).
    /// Alternatively, mp1 shows that c7 has an inverse.
    pub mp1: MulProofIntermediateTranscript<P>,

    /// mp2: the values produced multiplication proof for showing that c10 is a commitment
    /// to c9 * c8.
    pub mp2: MulProofIntermediateTranscript<P>,

    /// mp3: the values produced during the multiplication proof for showing that c11 is a commitment to c10*c10.
    pub mp3: MulProofIntermediateTranscript<P>,
    /// mp4: the values produced during the multiplication proof for showing that c13 is a commitment to c10*c12.
    pub mp4: MulProofIntermediateTranscript<P>,

    /// e1: the values produced during the equality proof for showing that c5 + c1 + c3 and c11 are commitments to the same value.
    pub e1: EqualityProofIntermediateTranscript<P>,
    /// e2: the values produced during the equality proof for showing that c6 + c2 and c13 are commitments to the same value.
    pub e2: EqualityProofIntermediateTranscript<P>,
}

impl<P: PedersenConfig> PointAddProtocol<P> for ZKAttestPointAddProof<P> {
    type Intermediate = ZKAttestPointAddProofIntermediate<P>;
    type IntermediateTranscript = ZKAttestPointAddProofIntermediateTranscript<P>;

    fn challenge_scalar(transcript: &mut Transcript) -> [u8; 64] {
        ZKAttestECPointAdditionTranscript::challenge_scalar(transcript, b"c")
    }

    /// make_intermediate_transcript. This function accepts a set of intermediates (`inter`) and builds
    /// a new intermediate transcript object from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate objects.
    fn make_intermediate_transcript(
        inter: ZKAttestPointAddProofIntermediate<P>,
    ) -> ZKAttestPointAddProofIntermediateTranscript<P> {
        ZKAttestPointAddProofIntermediateTranscript {
            c8: inter.c8.comm,
            c10: inter.c10.comm,
            c11: inter.c11.comm,
            c13: inter.c13.comm,
            mp1: MulProof::make_intermediate_transcript(inter.mpi1),
            mp2: MulProof::make_intermediate_transcript(inter.mpi2),
            mp3: MulProof::make_intermediate_transcript(inter.mpi3),
            mp4: MulProof::make_intermediate_transcript(inter.mpi4),
            e1: EqualityProof::make_intermediate_transcript(inter.ei1),
            e2: EqualityProof::make_intermediate_transcript(inter.ei2),
        }
    }

    /// create_intermediates_with_existing_commitments. This function returns all of the intermediate
    /// values for a proof that `t = a + b` using an existing set of commitments.
    /// This is primarily useful when the transcript that will be used to derive
    /// challenges has not yet been fully filled.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    /// * `ci` - the commitments to the points. In particular, c0 and c1 are commitments
    ///    to a.x and a.y. The same pattern holds for the others.
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
    ) -> ZKAttestPointAddProofIntermediate<P> {
        // We require that a != b.
        assert!(a != b);

        // Make the transcripts and build the relevant sub-proofs.
        Self::make_transcript(
            transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &c6.comm,
        );

        // Now make the proof that there's an inverse for b.x - a.x.
        let z2 = <P as PedersenConfig>::from_ob_to_sf((b.x - a.x).inverse().unwrap());

        let c7 = c3 - c1;
        let c8 = PedersenComm::new(z2, rng);

        // Make the multiplication proof for c8.
        let commit_one = PedersenComm {
            comm: <P as SWCurveConfig>::GENERATOR,
            r: <P as CurveConfig>::ScalarField::ZERO,
        };

        let mpi1 = MulProof::create_intermediates(transcript, rng, &c7, &c8, &commit_one);

        // Proof of c10
        let z3 = <P as PedersenConfig>::from_ob_to_sf(b.y - a.y);
        let c9 = c4 - c2;

        let z4 = z3 * z2; // b.y - a.y / b.x - a.x
        let c10 = PedersenComm::new(z4, rng);
        let mpi2 = MulProof::create_intermediates(transcript, rng, &c9, &c8, &c10);

        // Proof of c11
        let z5 = z4 * z4;
        let c11 = PedersenComm::new(z5, rng);
        let mpi3 = MulProof::create_intermediates(transcript, rng, &c10, &c10, &c11);

        // Proof of c13.
        let z6 = <P as PedersenConfig>::from_ob_to_sf(a.x - t.x);
        let c12 = c1 - c5;

        let z7 = z4 * z6; // z4 = b.y - a.y / (b.x - a.x), z6 = (a.x - t.x)
        let c13 = PedersenComm::new(z7, rng);

        let mpi4 = MulProof::create_intermediates(transcript, rng, &c10, &c12, &c13);

        // And now the remaining equality proofs.
        let c14 = c5 + c1 + c3;
        let ei1 = EqualityProof::create_intermediates(transcript, rng, &c14, &c11);

        // This is the corrected one.
        let c15 = c6 + c2;
        let ei2 = EqualityProof::create_intermediates(transcript, rng, &c13, &c15);

        ZKAttestPointAddProofIntermediate {
            c8,
            c10,
            c11,
            c13,
            mpi1,
            mpi2,
            mpi3,
            mpi4,
            ei1,
            ei2,
        }
    }

    /// create_proof_with_challenge. This function produces a ZKAttest point addition proof
    /// for `t = a + b` using the challenge `chal`.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (e.g `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `ci` - the commitments to the co-ordinates.
    /// * `chal` - the challenge.
    fn create_proof_with_challenge(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ZKAttestPointAddProofIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        // Now make the proof that there's an inverse for b.x - a.x.
        let z1 = <P as PedersenConfig>::from_ob_to_sf(b.x - a.x);
        let z2 = <P as PedersenConfig>::from_ob_to_sf((b.x - a.x).inverse().unwrap());

        let c7 = c3 - c1;
        // Make the multiplication proof for c8.
        let commit_one = PedersenComm {
            comm: <P as SWCurveConfig>::GENERATOR,
            r: <P as CurveConfig>::ScalarField::ZERO,
        };

        let mp1 = MulProof::create_proof_with_challenge(
            &z1,
            &z2,
            &inter.mpi1,
            &c7,
            &inter.c8,
            &commit_one,
            chal,
        );

        // Proof of c10
        let z3 = <P as PedersenConfig>::from_ob_to_sf(b.y - a.y);
        let c9 = c4 - c2;
        let z4 = z3 * z2; // b.y - a.y / b.x - a.x
        let mp2 = MulProof::create_proof_with_challenge(
            &z3,
            &z2,
            &inter.mpi2,
            &c9,
            &inter.c8,
            &inter.c10,
            chal,
        );

        // Proof of c11
        let mp3 = MulProof::create_proof_with_challenge(
            &z4,
            &z4,
            &inter.mpi3,
            &inter.c10,
            &inter.c10,
            &inter.c11,
            chal,
        );

        // Proof of c13.
        let z6 = <P as PedersenConfig>::from_ob_to_sf(a.x - t.x);
        let c12 = c1 - c5;
        let mp4 = MulProof::create_proof_with_challenge(
            &z4,
            &z6,
            &inter.mpi4,
            &inter.c10,
            &c12,
            &inter.c13,
            chal,
        );

        // And now for the remaining equality proofs.
        let c14 = c5 + c1 + c3;
        let eq1 = EqualityProof::create_proof_with_challenge(&inter.ei1, &c14, &inter.c11, chal);

        // This is the corrected one.
        let c15 = c6 + c2;
        let eq2 = EqualityProof::create_proof_with_challenge(&inter.ei2, &inter.c13, &c15, chal);

        Self {
            c8: inter.c8.comm,
            c10: inter.c10.comm,
            c11: inter.c11.comm,
            c13: inter.c13.comm,
            mp1,
            mp2,
            mp3,
            mp4,
            e1: eq1,
            e2: eq2,
        }
    }

    /// verify_with_challenge. This function verifies that the proof object held by `self` is valid.
    /// Note that this function uses `chal` as the challenge for this verification.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `ci` - the commitments.
    /// * `chal` - the challenge.
    fn verify_with_challenge(
        &self,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> bool {
        let c7 = (c3.into_group() - c1).into_affine();

        // Now we verify that c8 * c7 is a commitment to 1.
        // N.B We use the same fixed commitment to 1 as above.
        let commit_one = PedersenComm {
            comm: <P as SWCurveConfig>::GENERATOR,
            r: <P as CurveConfig>::ScalarField::ZERO,
        };

        let first = self
            .mp1
            .verify_with_challenge(&c7, &self.c8, &commit_one.comm, chal);

        // Proof of c10 = c9 * c10.
        // We recover c9 as c4 - c2.
        let c9 = (c4.into_group() - c2).into_affine();
        let second = self
            .mp2
            .verify_with_challenge(&c9, &self.c8, &self.c10, chal);

        // Proof of c11 = c10*c10
        let third = self
            .mp3
            .verify_with_challenge(&self.c10, &self.c10, &self.c11, chal);

        // Proof of c13 = c10 * c12.
        // We recover c12 as c1 - c5
        let c12 = (c1.into_group() - c5).into_affine();
        let fourth = self
            .mp4
            .verify_with_challenge(&self.c10, &c12, &self.c13, chal);

        // Verify that c5 + c1 + c3 == c11
        let c14 = (*c5 + c1 + c3).into_affine();
        let fifth = self.e1.verify_with_challenge(&c14, &self.c11, chal);

        // Verify that c13 == c6 + c2.
        let c15 = (*c6 + c2).into_affine();
        let sixth = self.e2.verify_with_challenge(&self.c13, &c15, chal);
        first && second && third && fourth && fifth && sixth
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize {
        self.c8.compressed_size()
            + self.c10.compressed_size()
            + self.c11.compressed_size()
            + self.c13.compressed_size()
            + self.mp1.serialized_size()
            + self.mp2.serialized_size()
            + self.mp3.serialized_size()
            + self.mp4.serialized_size()
            + self.e1.serialized_size()
            + self.e2.serialized_size()
    }

    fn add_proof_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        self.add_to_transcript(transcript, c1, c2, c3, c4, c5, c6);
    }
}

impl<P: PedersenConfig> ZKAttestPointAddProof<P> {
    /// make_transcript. This function simply adds all of the commitments to the `transcript`.
    /// # Arguments
    /// * `transcript` - the transcript object to which the commitments are added.
    /// * `c1` - the commitment to a.x
    /// * `c2` - the commitment to a.y
    /// * `c3` - the commitment to b.x
    /// * `c4` - the commitment to b.y
    /// * `c5` - the commitment to t.x
    /// * `c6` - the commitment to t.y
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        ZKAttestECPointAdditionTranscript::domain_sep(transcript);

        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.serialize_compressed(&mut compressed_bytes).unwrap();
        ZKAttestECPointAdditionTranscript::append_point(transcript, b"C6", &compressed_bytes[..]);
    }

    /// make_subproof_transcript. This function simply adds all of the relevant commitments and subproof
    /// information to the `transcript`. Note that this function accepts any kind of `MulProofTranscriptable`
    /// and `EqualityProofTranscriptable` objects.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `ci` - the commitments.
    /// * `mpi` - the multiplication proof transcript objects.
    /// * `epi` - the equality proof transcript objects.
    #[allow(clippy::too_many_arguments)]
    pub fn make_subproof_transcripts<
        MP: MulProofTranscriptable<Affine = sw::Affine<P>>,
        EP: EqualityProofTranscriptable<Affine = sw::Affine<P>>,
    >(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        c8: &sw::Affine<P>,
        c10: &sw::Affine<P>,
        c11: &sw::Affine<P>,
        c13: &sw::Affine<P>,
        mp1: &MP,
        mp2: &MP,
        mp3: &MP,
        mp4: &MP,
        ep1: &EP,
        ep2: &EP,
    ) {
        // Proof for c7 having an inverse.
        let c7 = (c3.into_group() - c1).into_affine();
        let commit_one = PedersenComm {
            comm: <P as SWCurveConfig>::GENERATOR,
            r: <P as CurveConfig>::ScalarField::ZERO,
        };

        mp1.add_to_transcript(transcript, &c7, c8, &commit_one.comm);

        // Proof of c10 = c9 * c10.
        // We recover c9 as c4 - c2.
        let c9 = (c4.into_group() - c2).into_affine();
        mp2.add_to_transcript(transcript, &c9, c8, c10);
        mp3.add_to_transcript(transcript, c10, c10, c11);

        let c12 = (c1.into_group() - c5).into_affine();
        mp4.add_to_transcript(transcript, c10, &c12, c13);

        let c14 = (c5.into_group() + c1 + c3).into_affine();
        ep1.add_to_transcript(transcript, &c14, c11);

        // Verify that c13 == c6 + c2.
        let c15 = (c6.into_group() + c2).into_affine();
        ep2.add_to_transcript(transcript, c13, &c15);
    }
}

impl<P: PedersenConfig> ZKAttestPointAddProofTranscriptable<P> for ZKAttestPointAddProof<P> {
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        ZKAttestPointAddProof::make_transcript(transcript, c1, c2, c3, c4, c5, c6);

        ZKAttestPointAddProof::make_subproof_transcripts(
            transcript, c1, c2, c3, c4, c5, c6, &self.c8, &self.c10, &self.c11, &self.c13,
            &self.mp1, &self.mp2, &self.mp3, &self.mp4, &self.e1, &self.e2,
        );
    }
}

impl<P: PedersenConfig> ZKAttestPointAddProofTranscriptable<P>
    for ZKAttestPointAddProofIntermediate<P>
{
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        ZKAttestPointAddProof::make_transcript(transcript, c1, c2, c3, c4, c5, c6);
        ZKAttestPointAddProof::make_subproof_transcripts(
            transcript,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            &self.c8.comm,
            &self.c10.comm,
            &self.c11.comm,
            &self.c13.comm,
            &self.mpi1,
            &self.mpi2,
            &self.mpi3,
            &self.mpi4,
            &self.ei1,
            &self.ei2,
        );
    }
}

impl<P: PedersenConfig> ZKAttestPointAddProofTranscriptable<P>
    for ZKAttestPointAddProofIntermediateTranscript<P>
{
    type Affine = sw::Affine<P>;
    fn add_to_transcript(
        &self,
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
    ) {
        ZKAttestPointAddProof::make_transcript(transcript, c1, c2, c3, c4, c5, c6);

        ZKAttestPointAddProof::make_subproof_transcripts(
            transcript, c1, c2, c3, c4, c5, c6, &self.c8, &self.c10, &self.c11, &self.c13,
            &self.mp1, &self.mp2, &self.mp3, &self.mp4, &self.e1, &self.e2,
        );
    }
}

impl<P: PedersenConfig> ZKAttestPointAddProofIntermediateTranscript<P> {
    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    pub fn serialized_size(&self) -> usize {
        self.c8.compressed_size()
            + self.c10.compressed_size()
            + self.c11.compressed_size()
            + self.c13.compressed_size()
            + self.mp1.serialized_size()
            + self.mp2.serialized_size()
            + self.mp3.serialized_size()
            + self.mp4.serialized_size()
            + self.e1.serialized_size()
            + self.e2.serialized_size()
    }
}
