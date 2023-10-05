//! Defines a protocol for proof of elliptic curve point addition.
//! Namely, this protocol proves that A + B = T, for A, B, T \in E(F_{q}).
//! This protocol is the same as the protocol described in Theorem 4 of the CDLS paper.

use ark_ec::{
    short_weierstrass::{self as sw},
    AffineRepr, CurveConfig, CurveGroup,
};
use merlin::Transcript;

use ark_ff::fields::Field;
use ark_serialize::CanonicalSerialize;

use rand::{CryptoRng, RngCore};

use crate::{
    mul_protocol::{
        MulProof, MulProofIntermediate, MulProofIntermediateTranscript, MulProofTranscriptable,
    },
    opening_protocol::{
        OpeningProof, OpeningProofIntermediate, OpeningProofIntermediateTranscript,
        OpeningProofTranscriptable,
    },
    pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig,
    point_add::PointAddProtocol,
    transcript::ECPointAdditionTranscript,
};

/// ECPointAddProofTranscriptable. This trait provides a notion of `Transcriptable` which implies that
/// a particular struct can be, in some sense, added to the transcript for a point addition proof.
pub trait ECPointAddProofTranscriptable<P: PedersenConfig> {
    /// add_to_transcript. This function adds all sub-proof information to the transcript
    /// object. This is typically used when the ECPointAddProtocol is invoked as part of a larger
    /// proof.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object that's used.
    /// * `ci` - the commitments.
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

/// ECPointAddProof. This struct acts as a container for an Elliptic Curve Point Addition proof.
/// Essentially, this struct can be used to create new proofs (via ```create```), and verify
/// existing proofs (via ```verify```).
/// In this documentation we use the convention that we are trying to prove t = a + b.
pub struct ECPointAddProof<P: PedersenConfig> {
    /// c7: the commitment to tau = (b.y - a.y)/(b.x - a.x)
    pub c7: sw::Affine<P>,

    /// mp1: the multiplication proof that verifies that equation 1 holds.
    pub mp1: MulProof<P>,

    /// mp2: the multiplication proof that verifies that equation 2 holds.
    pub mp2: MulProof<P>,

    /// mp3: the multiplication proof that verifies that equation 3 holds.
    pub mp3: MulProof<P>,

    /// op: the opening proof of C2.
    pub op: OpeningProof<P>,
}

/// ECPointAddIntermediate. This struct acts as a container for the intermediate values of an Elliptic Curve Point
/// addition proof. Essentially, this struct should be used when the ECPointAddProof is a sub-portion of a larger
/// protocol.
pub struct ECPointAddIntermediate<P: PedersenConfig> {
    /// c7: the commitment to tau = (b.y - a.y)/(b.x - a.x)
    pub c7: PedersenComm<P>,

    /// mpi1: the intermediates for verifying equation 1.
    pub mpi1: MulProofIntermediate<P>,
    /// mpi2: the intermediates for verifying equation 2.
    pub mpi2: MulProofIntermediate<P>,
    /// mpi3: the intermediates for verifying equation 3.
    pub mpi3: MulProofIntermediate<P>,
    /// opi: the intermediates for verifying the opening of C2.
    pub opi: OpeningProofIntermediate<P>,
}

/// ECPointAddIntermediateTranscript. This struct provides a wrapper for every input
/// into the transcript i.e everything that's in `ECPointAddIntermediate` except from
/// the randomness values.
pub struct ECPointAddIntermediateTranscript<P: PedersenConfig> {
    /// c7: the commitment to tau = (b.y - a.y)/(b.x - a.x)
    pub c7: sw::Affine<P>,

    /// mpi1: the intermediates for verifying equation 1.
    pub mpi1: MulProofIntermediateTranscript<P>,
    /// mpi2: the intermediates for verifying equation 2.
    pub mpi2: MulProofIntermediateTranscript<P>,
    /// mpi3: the intermediates for verifying equation 3.
    pub mpi3: MulProofIntermediateTranscript<P>,
    /// opi: the intermediates for verifying the opening of C2.
    pub opi: OpeningProofIntermediateTranscript<P>,
}

impl<P: PedersenConfig> PointAddProtocol<P> for ECPointAddProof<P> {
    type Intermediate = ECPointAddIntermediate<P>;
    type IntermediateTranscript = ECPointAddIntermediateTranscript<P>;

    fn challenge_scalar(transcript: &mut Transcript) -> [u8; 64] {
        ECPointAdditionTranscript::challenge_scalar(transcript, b"c")
    }

    /// make_intermediate_transcript. This function accepts a set of intermediate values (`inter`)
    /// and builds a new ECPointAddProofIntermediateTranscript from `inter`.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    fn make_intermediate_transcript(
        inter: ECPointAddIntermediate<P>,
    ) -> ECPointAddIntermediateTranscript<P> {
        ECPointAddIntermediateTranscript {
            c7: inter.c7.comm,
            mpi1: MulProof::make_intermediate_transcript(inter.mpi1),
            mpi2: MulProof::make_intermediate_transcript(inter.mpi2),
            mpi3: MulProof::make_intermediate_transcript(inter.mpi3),
            opi: OpeningProof::make_intermediate_transcript(inter.opi),
        }
    }

    /// create_intermediates_with_existing_commitments. This function returns a new set of
    /// intermediaries for a proof that  `t = a + b` using already existing commitments to `a`, `b`, and `t`.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    /// * `ci` - the commitments to the various co-ordinates.
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
    ) -> ECPointAddIntermediate<P> {
        // This proof does not show work for point doubling.
        assert!(a != b);
        // c7 is the commitment to tau, the gradient.
        let tau = (b.y - a.y) * ((b.x - a.x).inverse().unwrap());
        let taua = <P as PedersenConfig>::from_ob_to_sf(tau);
        let c7 = PedersenComm::new(taua, rng);

        // Now we begin the stage of incorporating everything into the
        // transcript. We do this by creating the intermediates for each
        // proof (which adds to the transcript in turn).
        Self::make_transcript(
            transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &c6.comm, &c7.comm,
        );

        // These are the temporaries for the first multiplication proof, which
        // verifies that (b.x - a.x)*tau = b.y - a.y.
        let z1 = c3 - c1; // This is the commitment for b.x - a.x.
        let z2 = c4 - c2; // This is the commitment for b.y - a.y.
        let mpi1 = MulProof::create_intermediates(transcript, rng, &z1, &c7, &z2);

        // These are the temporaries for the second multiplication proof, which verifies that
        // tau^2 = a.x + b.x + t.x.
        let z4 = c1 + c3 + c5; // This is the commitment to a.x + b.x + t.x.
        let mpi2 = MulProof::create_intermediates(transcript, rng, &c7, &c7, &z4);

        // These are the temporaries for the third multiplication proof, which verifies that
        // tau*(a.x - t.x) = a.y + t.y.
        let z5 = c1 - c5; // The commitment to a.x - t.x
        let z6 = c2 + c6; // The commitment to a.y + t.y.
        let mpi3 = MulProof::create_intermediates(transcript, rng, &c7, &z5, &z6);

        // And, finally, the intermediates for the Opening proof.
        // This proves that C2 opens to a.y.
        let opi = OpeningProof::create_intermediates(transcript, rng, c2);

        // Now we return the intermediates.
        ECPointAddIntermediate {
            c7,
            mpi1,
            mpi2,
            mpi3,
            opi,
        }
    }

    /// create_proof_with_challenge. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined challenge (`chal`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `ci` - the commitments.
    /// * `chal` - the challenge point.
    fn create_proof_with_challenge(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ECPointAddIntermediate<P>,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        // Recompute tau and all of the other, extra data.
        let tau = (b.y - a.y) * ((b.x - a.x).inverse().unwrap());
        let taua = <P as PedersenConfig>::from_ob_to_sf(tau);

        let z1 = c3 - c1; // This is the commitment for b.x - a.x.
        let z2 = c4 - c2; // This is the commitment for b.y - a.y.
        let x1 = <P as PedersenConfig>::from_ob_to_sf(b.x - a.x);
        let z4 = c1 + c3 + c5; // This is the commitment to a.x + b.x + t.x.
        let x3 = <P as PedersenConfig>::from_ob_to_sf(a.x - t.x); // Value of a.x - t.x
        let z5 = c1 - c5; // The commitment to a.x - t.x
        let z6 = c2 + c6; // The commitment to a.y + t.y.
        let ay_sf = <P as PedersenConfig>::from_ob_to_sf(a.y);

        // Now just use the existing intermediate values to fill out the full proofs.
        let mp1 = MulProof::create_proof_with_challenge(
            &x1,
            &taua,
            &inter.mpi1,
            &z1,
            &inter.c7,
            &z2,
            chal,
        );

        let mp2 = MulProof::create_proof_with_challenge(
            &taua,
            &taua,
            &inter.mpi2,
            &inter.c7,
            &inter.c7,
            &z4,
            chal,
        );

        let mp3 = MulProof::create_proof_with_challenge(
            &taua,
            &x3,
            &inter.mpi3,
            &inter.c7,
            &z5,
            &z6,
            chal,
        );

        let op = OpeningProof::create_proof_with_challenge(&ay_sf, &inter.opi, c2, chal);

        // And now we just return.
        Self {
            c7: inter.c7.comm,
            mp1,
            mp2,
            mp3,
            op,
        }
    }

    /// verify_with_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge (`chal`).
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
        let z1 = (c3.into_group() - c1).into_affine();
        let z2 = &self.c7;
        let z3 = (c4.into_group() - c2).into_affine();
        let z4 = (c1.into_group() + c3 + c5).into_affine();
        let z5 = (c1.into_group() - c5).into_affine();
        let z6 = (c2.into_group() + c6).into_affine();

        self.mp1.verify_with_challenge(&z1, z2, &z3, chal)
            && self
                .mp2
                .verify_with_challenge(&self.c7, &self.c7, &z4, chal)
            && self.mp3.verify_with_challenge(z2, &z5, &z6, chal)
            && self.op.verify_with_challenge(c2, chal)
    }

    /// serialized_size. Returns the number of bytes needed to represent this proof object once serialised.
    fn serialized_size(&self) -> usize {
        self.c7.compressed_size()
            + self.mp1.serialized_size()
            + self.mp2.serialized_size()
            + self.mp3.serialized_size()
            + self.op.serialized_size()
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

impl<P: PedersenConfig> ECPointAddProof<P> {
    #[allow(clippy::too_many_arguments)]
    /// make_transcript. This function simply loads all commitments `c_i` into the
    /// `transcript` object. This can then be used for proving or verifying statements.
    /// # Arguments
    /// * `transcript` - the transcript object to modify.
    /// * `c_i` - the commitments that are being added to the transcript.
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        c7: &sw::Affine<P>,
    ) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        ECPointAdditionTranscript::domain_sep(transcript);

        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C6", &compressed_bytes[..]);

        c7.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C7", &compressed_bytes[..]);
    }

    /// make_subproof_transcripts. This function instantiates the transcripts for the
    /// subproofs. This is typically used when multiple sub-proofs comprise a larger
    /// proof.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `ci` - the commitments to the various portions of the ECPointAddProof.
    /// * `mp1` - the multiplication proof sub-object that verifies Equation 1.
    /// * `mp2` - the multiplication proof sub-object that verifies Equation 2.
    /// * `mp3` - the multiplication proof sub-object that verifies Equation 3.
    /// * `op`  - the opening proof sub-object that verifies knowledge of C2.
    #[allow(clippy::too_many_arguments)]
    pub fn make_subproof_transcripts<
        MP: MulProofTranscriptable<Affine = sw::Affine<P>>,
        OP: OpeningProofTranscriptable<Affine = sw::Affine<P>>,
    >(
        transcript: &mut Transcript,
        c1: &sw::Affine<P>,
        c2: &sw::Affine<P>,
        c3: &sw::Affine<P>,
        c4: &sw::Affine<P>,
        c5: &sw::Affine<P>,
        c6: &sw::Affine<P>,
        c7: &sw::Affine<P>,
        mp1: &MP,
        mp2: &MP,
        mp3: &MP,
        op: &OP,
    ) {
        let z1 = (c3.into_group() - c1).into_affine();
        let z2 = &c7;
        let z3 = (c4.into_group() - c2).into_affine();
        let z4 = (c1.into_group() + c3 + c5).into_affine();
        let z5 = (c1.into_group() - c5).into_affine();
        let z6 = (c2.into_group() + c6).into_affine();

        // Just instantiate each sub-portion together.
        mp1.add_to_transcript(transcript, &z1, z2, &z3);
        mp2.add_to_transcript(transcript, c7, c7, &z4);
        mp3.add_to_transcript(transcript, z2, &z5, &z6);
        op.add_to_transcript(transcript, c2);
    }
}

impl<P: PedersenConfig> ECPointAddProofTranscriptable<P> for ECPointAddProof<P> {
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
        // Just build each bit in turn.
        ECPointAddProof::make_transcript(transcript, c1, c2, c3, c4, c5, c6, &self.c7);
        ECPointAddProof::make_subproof_transcripts(
            transcript, c1, c2, c3, c4, c5, c6, &self.c7, &self.mp1, &self.mp2, &self.mp3, &self.op,
        );
    }
}

impl<P: PedersenConfig> ECPointAddProofTranscriptable<P> for ECPointAddIntermediate<P> {
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
        // Just build each bit in turn.
        ECPointAddProof::make_transcript(transcript, c1, c2, c3, c4, c5, c6, &self.c7.comm);
        ECPointAddProof::make_subproof_transcripts(
            transcript,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            &self.c7.comm,
            &self.mpi1,
            &self.mpi2,
            &self.mpi3,
            &self.opi,
        );
    }
}

impl<P: PedersenConfig> ECPointAddProofTranscriptable<P> for ECPointAddIntermediateTranscript<P> {
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
        // Just build each bit in turn.
        ECPointAddProof::make_transcript(transcript, c1, c2, c3, c4, c5, c6, &self.c7);
        ECPointAddProof::make_subproof_transcripts(
            transcript, c1, c2, c3, c4, c5, c6, &self.c7, &self.mpi1, &self.mpi2, &self.mpi3,
            &self.opi,
        );
    }
}
