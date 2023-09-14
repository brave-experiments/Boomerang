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
    mul_protocol::{MulProof, MulProofIntermediate},
    opening_protocol::{OpeningProof, OpeningProofIntermediate},
    pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig,
    transcript::ECPointAdditionTranscript,
};

/// ECPointAddProof. This struct acts as a container for an Elliptic Curve Point Addition proof.
/// Essentially, this struct can be used to create new proofs (via ```create```), and verify
/// existing proofs (via ```verify```).
/// In this documentation we use the convention that we are trying to prove t = a + b.
pub struct ECPointAddProof<P: PedersenConfig> {
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
    pub c1: PedersenComm<P>,
    pub c2: PedersenComm<P>,
    pub c3: PedersenComm<P>,
    pub c4: PedersenComm<P>,
    pub c5: PedersenComm<P>,
    pub c6: PedersenComm<P>,
    pub c7: PedersenComm<P>,

    pub mpi1: MulProofIntermediate<P>,
    pub mpi2: MulProofIntermediate<P>,
    pub mpi3: MulProofIntermediate<P>,
    pub opi: OpeningProofIntermediate<P>,
}

impl<P: PedersenConfig> ECPointAddProof<P> {
    #[allow(clippy::too_many_arguments)]
    /// make_transcript. This function simply loads all commitments `c_i` into the
    /// `transcript` object. This can then be used for proving or verifying statements.
    /// # Arguments
    /// * `transcript` - the transcript object to modify.
    /// * `c_i` - the commitments that are being added to the transcript.
    fn make_transcript(
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

    /// create_commitments_to_coords. This function accepts a series of affine points (from the underyling OCurve)
    /// and creates commitments to each co-ordinate of each point, returning the results as a tuple.
    /// The formed commitments are commitments over the relevant T Curve.
    /// # Arguments
    /// * `a`: one of the summands.
    /// * `b`: the other summand.
    /// * `t`: the target point (i.e `t = a + b`).
    /// * `rng`: the RNG that is used. Must be cryptographically secure.
    // It's not _that_ complicated, Clippy.
    #[allow(clippy::type_complexity)]
    fn create_commitments_to_coords<T: RngCore + CryptoRng>(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        rng: &mut T,
    ) -> (
        PedersenComm<P>,
        PedersenComm<P>,
        PedersenComm<P>,
        PedersenComm<P>,
        PedersenComm<P>,
        PedersenComm<P>,
    ) {
        (
            <P as PedersenConfig>::make_commitment_from_other(a.x, rng),
            <P as PedersenConfig>::make_commitment_from_other(a.y, rng),
            <P as PedersenConfig>::make_commitment_from_other(b.x, rng),
            <P as PedersenConfig>::make_commitment_from_other(b.y, rng),
            <P as PedersenConfig>::make_commitment_from_other(t.x, rng),
            <P as PedersenConfig>::make_commitment_from_other(t.y, rng),
        )
    }

    /// create_intermediates. This function returns a new set of intermediaries for a proof that
    /// `t = a + b` using already existing commitments to `a`, `b`, and `t`. This function
    /// will generate new commitments to `a`, `b`, and `t`.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    pub fn create_intermediates<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> ECPointAddIntermediate<P> {
        let (c1, c2, c3, c4, c5, c6) = Self::create_commitments_to_coords(a, b, t, rng);
        Self::create_intermediates_with_existing_commitments(
            transcript, rng, a, b, t, &c1, &c2, &c3, &c4, &c5, &c6,
        )
    }

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
    #[allow(clippy::too_many_arguments)]
    pub fn create_intermediates_with_existing_commitments<T: RngCore + CryptoRng>(
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
            c1: *c1,
            c2: *c2,
            c3: *c3,
            c4: *c4,
            c5: *c5,
            c6: *c6,
            c7,
            mpi1,
            mpi2,
            mpi3,
            opi,
        }
    }

    /// create_with_existing_commitments. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing commitments `c1,...,c6`.
    /// /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used. Must be cryptographically secure.
    /// * `a` - one of the summands.
    /// * `b` - the other summands.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `ci` - the commitments.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_existing_commitments<T: RngCore + CryptoRng>(
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
    ) -> Self {
        let inter = Self::create_intermediates_with_existing_commitments(
            transcript, rng, a, b, t, c1, c2, c3, c4, c5, c6,
        );

        // Make the challenge.
        let chal_buf = ECPointAdditionTranscript::challenge_scalar(transcript, b"c");

        // Now just delegate to the other proof routines.
        Self::create_proof(a, b, t, &inter, &chal_buf)
    }

    /// create_proof. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined slice of challenge bytes (`chal_buf`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `chal_buf` - the buffer that contains the challenge bytes.
    pub fn create_proof(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ECPointAddIntermediate<P>,
        chal_buf: &[u8],
    ) -> Self {
        // Just return the result of creating all of the sub-proofs.
        Self::create_proof_with_challenge(
            a,
            b,
            t,
            inter,
            &<P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1),
        )
    }

    /// create_proof_with_challenge. This function returns a new proof of elliptic curve point addition
    /// for `t = a + b` using the existing intermediate values held in `inter`. This function also uses
    /// a pre-determined challenge (`chal`) when generating all sub-proofs.
    /// # Arguments
    /// * `a` - one of the summands.
    /// * `b` - the other summand.
    /// * `t` - the target point (i.e `t = a + b`).
    /// * `inter` - the intermediate values.
    /// * `chal` - the challenge point.
    pub fn create_proof_with_challenge(
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
        inter: &ECPointAddIntermediate<P>,
        chal: &<P as CurveConfig>::ScalarField,
    ) -> Self {
        // Recompute tau and all of the other, extra data.
        let tau = (b.y - a.y) * ((b.x - a.x).inverse().unwrap());
        let taua = <P as PedersenConfig>::from_ob_to_sf(tau);

        let z1 = inter.c3 - inter.c1; // This is the commitment for b.x - a.x.
        let z2 = inter.c4 - inter.c2; // This is the commitment for b.y - a.y.
        let x1 = <P as PedersenConfig>::from_ob_to_sf(b.x - a.x);
        let z4 = inter.c1 + inter.c3 + inter.c5; // This is the commitment to a.x + b.x + t.x.
        let x3 = <P as PedersenConfig>::from_ob_to_sf(a.x - t.x); // Value of a.x - t.x
        let z5 = inter.c1 - inter.c5; // The commitment to a.x - t.x
        let z6 = inter.c2 + inter.c6; // The commitment to a.y + t.y.
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
        let op = OpeningProof::create_proof_with_challenge(&ay_sf, &inter.opi, &inter.c2, chal);

        // And now we just return.
        Self {
            c1: inter.c1.comm,
            c2: inter.c2.comm,
            c3: inter.c3.comm,
            c4: inter.c4.comm,
            c5: inter.c5.comm,
            c6: inter.c6.comm,
            c7: inter.c7.comm,
            mp1,
            mp2,
            mp3,
            op,
        }
    }

    /// create. This function returns a new proof of elliptic curve addition point addition
    /// for `t = a + b`.
    /// # Arguments
    /// * `transcript` - the transcript object that is modified.
    /// * `rng` - the RNG that is used. Must be cryptographically secure.
    /// * `a` - one of the summands.
    /// * `b` - the other summands.
    /// * `t` - the target point (i.e `t = a + b`).
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // This proof does not show work for point doubling.
        assert!(a != b);
        // Commit to each of the co-ordinate pairs.
        let (c1, c2, c3, c4, c5, c6) = Self::create_commitments_to_coords(a, b, t, rng);
        Self::create_with_existing_commitments(
            transcript, rng, a, b, t, &c1, &c2, &c3, &c4, &c5, &c6,
        )
    }

    /// add_to_transcript. This function adds all sub-proof information to the transcript
    /// object. This is typically used when the ECPointAddProtocol is invoked as part of a larger
    /// proof.
    /// # Arguments
    /// * `self` - the proof object.
    /// * `transcript` - the transcript object that's used.
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        Self::make_transcript(
            transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6, &self.c7,
        );

        let z1 = (self.c3.into_group() - self.c1).into_affine();
        let z2 = &self.c7;
        let z3 = (self.c4.into_group() - self.c2).into_affine();
        let z4 = (self.c1 + self.c3 + self.c5).into_affine();
        let z5 = (self.c1.into_group() - self.c5).into_affine();
        let z6 = (self.c2.into_group() + self.c6).into_affine();

        // Rebuild the rest of the transcript.
        self.mp1.add_to_transcript(transcript, &z1, z2, &z3);
        self.mp2
            .add_to_transcript(transcript, &self.c7, &self.c7, &z4);
        self.mp3.add_to_transcript(transcript, z2, &z5, &z6);
        self.op.add_to_transcript(transcript, &self.c2);
    }

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    pub fn verify(&self, transcript: &mut Transcript) -> bool {
        // Rebuild the whole transcript.
        self.add_to_transcript(transcript);

        // Now produce the "right" challenge object. We do this in a generic way (see the pedersen config for more)
        // but essentially we map the lowest bit of `chal_buf` to (-1, 1) (mod p).
        // Make the challenge.
        let chal_buf = ECPointAdditionTranscript::challenge_scalar(transcript, b"c");
        self.verify_proof(&chal_buf)
    }

    /// verify_proof. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge buffer (`chal_buf`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `chal_buf` - the buffer containing the challenge bytes.
    pub fn verify_proof(&self, chal_buf: &[u8]) -> bool {
        let chal = <P as PedersenConfig>::make_single_bit_challenge(chal_buf.last().unwrap() & 1);
        self.verify_with_challenge(&chal)
    }

    /// verify_with_challenge. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// In other words, this function returns true if the proof shows that `t = a + b` for previously
    /// committed values of `t`, `a` and `b`.
    /// Note that this function allows the caller to pass in a pre-determined challenge (`chal`).
    /// # Arguments
    /// * `self` - the proof object.
    /// * `chal` - the challenge.
    pub fn verify_with_challenge(&self, chal: &<P as CurveConfig>::ScalarField) -> bool {
        let z1 = (self.c3.into_group() - self.c1).into_affine();
        let z2 = &self.c7;
        let z3 = (self.c4.into_group() - self.c2).into_affine();
        let z4 = (self.c1 + self.c3 + self.c5).into_affine();
        let z5 = (self.c1.into_group() - self.c5).into_affine();
        let z6 = (self.c2.into_group() + self.c6).into_affine();

        self.mp1.verify_with_challenge(&z1, z2, &z3, chal)
            && self
                .mp2
                .verify_with_challenge(&self.c7, &self.c7, &z4, chal)
            && self.mp3.verify_with_challenge(z2, &z5, &z6, chal)
            && self.op.verify_with_challenge(&self.c2, chal)
    }
}
