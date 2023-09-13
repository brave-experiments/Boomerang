//! Defines a protocol for proof of elliptic curve point addition.
//! Namely, this protocol proves that A + B = T, for A, B, T \in E(F_{q}).
//! This protocol is the same as the protocol described in Theorem 4 of the CDLS paper.

use ark_ec::{
    short_weierstrass::{self as sw},
    AffineRepr, CurveGroup,
};
use merlin::Transcript;

use ark_ff::fields::Field;
use ark_serialize::CanonicalSerialize;

use rand::{CryptoRng, RngCore};

use crate::{
    mul_protocol::MulProof, opening_protocol::OpeningProof, pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig, transcript::ECPointAdditionTranscript,
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

impl<P: PedersenConfig> ECPointAddProof<P> {
    /// This is just to circumvent an annoying issue with Rust's current generics system.
    const MPSIZE: usize = MulProof::<P>::CHAL_SIZE;
    const OPSIZE: usize = OpeningProof::<P>::CHAL_SIZE;
    pub const CHAL_SIZE: usize = 3 * Self::MPSIZE + Self::OPSIZE;

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

    /// create_with_existing_commitments. This constructor returns a new Elliptic Curve addition proof
    /// that `t = a + b` using already existing commitments to `a`, `b`, and `t`.
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
        // This proof does not show work for point doubling.
        assert!(a != b);
        // c7 is the commitment to tau, the gradient.
        let tau = (b.y - a.y) * ((b.x - a.x).inverse().unwrap());
        let taua = <P as PedersenConfig>::from_ob_to_sf(tau);
        let c7 = PedersenComm::new(taua, rng);

        // Now we begin the stage of incorporating everything into the
        // transcript. We do this by creating the intermediates for each
        // proof (which adds to the transcript in turn), before generating a long
        // challenge (with enough space for each sub-proof). We then, finally,
        // split up this challenge into smaller slices that can be used by each
        // individual proof.
        Self::make_transcript(
            transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &c6.comm, &c7.comm,
        );

        // These are the temporaries for the first multiplication proof, which
        // verifies that (b.x - a.x)*tau = b.y - a.y.
        let z1 = c3 - c1; // This is the commitment for b.x - a.x.
        let z2 = c4 - c2; // This is the commitment for b.y - a.y.

        let x1 = <P as PedersenConfig>::from_ob_to_sf(b.x - a.x);
        let mpi1 = MulProof::create_intermediates(transcript, rng, &z1, &c7, &z2);

        // These are the temporaries for the second multiplication proof, which verifies that
        // tau^2 = a.x + b.x + t.x.
        let z4 = c1 + c3 + c5; // This is the commitment to a.x + b.x + t.x.
        let mpi2 = MulProof::create_intermediates(transcript, rng, &c7, &c7, &z4);

        // These are the temporaries for the third multiplication proof, which verifies that
        // tau*(a.x - t.x) = a.y + t.y.
        let x3 = <P as PedersenConfig>::from_ob_to_sf(a.x - t.x); // Value of a.x - t.x
        let z5 = c1 - c5; // The commitment to a.x - t.x
        let z6 = c2 + c6; // The commitment to a.y + t.y.
        let mpi3 = MulProof::create_intermediates(transcript, rng, &c7, &z5, &z6);

        // And, finally, the intermediates for the Opening proof.
        // This proves that C2 opens to a.y.
        let ay_sf = <P as PedersenConfig>::from_ob_to_sf(a.y);
        let opi = OpeningProof::create_intermediates(transcript, rng, c2);

        // Now we make a very large challenge and create the various proofs from the
        // intermediates.
        let chal_buf = ECPointAdditionTranscript::challenge_scalar(transcript, b"c");

        // Make sure it all lines up.
        //assert!(Self::CHAL_SIZE == EC_POINT_CHALLENGE_SIZE);

        // Make the sub-challenges.
        let mp1chal = &chal_buf[0..Self::MPSIZE];
        let mp2chal = &chal_buf[Self::MPSIZE..2 * Self::MPSIZE];
        let mp3chal = &chal_buf[2 * Self::MPSIZE..3 * Self::MPSIZE];
        let opchal = &chal_buf[3 * Self::MPSIZE..];

        // And now we build the sub-proofs before returning.
        let mp1 = MulProof::create_proof(&x1, &taua, &mpi1, &z1, &c7, &z2, mp1chal);
        let mp2 = MulProof::create_proof(&taua, &taua, &mpi2, &c7, &c7, &z4, mp2chal);
        let mp3 = MulProof::create_proof(&taua, &x3, &mpi3, &c7, &z5, &z6, mp3chal);
        let op = OpeningProof::create_proof(&ay_sf, &opi, c2, opchal);

        // And now we just return.
        Self {
            c1: c1.comm,
            c2: c2.comm,
            c3: c3.comm,
            c4: c4.comm,
            c5: c5.comm,
            c6: c6.comm,
            c7: c7.comm,
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

        let c1 = <P as PedersenConfig>::make_commitment_from_other(a.x, rng);
        let c2 = <P as PedersenConfig>::make_commitment_from_other(a.y, rng);
        let c3 = <P as PedersenConfig>::make_commitment_from_other(b.x, rng);
        let c4 = <P as PedersenConfig>::make_commitment_from_other(b.y, rng);
        let c5 = <P as PedersenConfig>::make_commitment_from_other(t.x, rng);
        let c6 = <P as PedersenConfig>::make_commitment_from_other(t.y, rng);

        Self::create_with_existing_commitments(
            transcript, rng, a, b, t, &c1, &c2, &c3, &c4, &c5, &c6,
        )
    }

    /// verify. This function returns true if the proof held by `self` is valid, and false otherwise.
    /// # Arguments
    /// * `self` - the proof that is being verified.
    /// * `transcript` - the transcript object that's used.
    pub fn verify(&self, transcript: &mut Transcript) -> bool {
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

        // Make the challenges and sub-challenges.
        let chal_buf = ECPointAdditionTranscript::challenge_scalar(transcript, b"c");
        let mp1chal = &chal_buf[0..Self::MPSIZE];
        let mp2chal = &chal_buf[Self::MPSIZE..2 * Self::MPSIZE];
        let mp3chal = &chal_buf[2 * Self::MPSIZE..3 * Self::MPSIZE];
        let opchal = &chal_buf[3 * Self::MPSIZE..];

        self.mp1.verify_with_challenge(&z1, z2, &z3, mp1chal)
            && self
                .mp2
                .verify_with_challenge(&self.c7, &self.c7, &z4, mp2chal)
            && self.mp3.verify_with_challenge(z2, &z5, &z6, mp3chal)
            && self.op.verify_with_challenge(&self.c2, opchal)
    }
}
