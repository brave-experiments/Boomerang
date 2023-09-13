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
    equality_protocol::EqualityProof, mul_protocol::MulProof, pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig, transcript::ZKAttestECPointAdditionTranscript,
};

/// ZKAttestPointAddProof. This struct acts as a container for the ZKAttest Point addition proof.
/// New proof objects can be made via the `create` function, whereas existing
/// proofs may be verified via the `verify` function.
/// Note that this struct's documentation uses the convention that we are proving `t = a + b`.
pub struct ZKAttestPointAddProof<P: PedersenConfig> {
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
    fn make_transcript(
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

    /// create. This function returns a new proof that `t = a + b`.
    /// # Arguments
    /// * `transcript` - the transcript object.
    /// * `rng` - the random number generator. This must be a cryptographically secure RNG.
    /// * `a` - one of the components of the sum.
    /// * `b` - the other component of the sum.
    /// * `t` - the target point (i.e t = a + b).
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a: sw::Affine<<P as PedersenConfig>::OCurve>,
        b: sw::Affine<<P as PedersenConfig>::OCurve>,
        t: sw::Affine<<P as PedersenConfig>::OCurve>,
    ) -> Self {
        // This proof requires that a != b.
        assert!(a != b);

        // Commit to each of the co-ordinate pairs.
        let c1 = <P as PedersenConfig>::make_commitment_from_other(a.x, rng);
        let c2 = <P as PedersenConfig>::make_commitment_from_other(a.y, rng);
        let c3 = <P as PedersenConfig>::make_commitment_from_other(b.x, rng);
        let c4 = <P as PedersenConfig>::make_commitment_from_other(b.y, rng);
        let c5 = <P as PedersenConfig>::make_commitment_from_other(t.x, rng);
        let c6 = <P as PedersenConfig>::make_commitment_from_other(t.y, rng);

        Self::make_transcript(
            transcript, &c1.comm, &c2.comm, &c3.comm, &c4.comm, &c5.comm, &c6.comm,
        );

        // Now make the proof that there's an inverse for b.x - a.x.
        let z1 = <P as PedersenConfig>::from_ob_to_sf(b.x - a.x);
        let z2 = <P as PedersenConfig>::from_ob_to_sf((b.x - a.x).inverse().unwrap());

        let c7 = &c3 - &c1;
        let c8 = PedersenComm::new(z2, rng);

        // Make the multiplication proof for c8.
        let commit_one = PedersenComm {
            comm: <P as SWCurveConfig>::GENERATOR,
            r: <P as CurveConfig>::ScalarField::ZERO,
        };
        let mp1 = MulProof::create(transcript, rng, &z1, &z2, &c7, &c8, &commit_one);

        // Proof of c10
        let z3 = <P as PedersenConfig>::from_ob_to_sf(b.y - a.y);
        let c9 = &c4 - &c2;

        let z4 = z3 * z2; // b.y - a.y / b.x - a.x
        let c10 = PedersenComm::new(z4, rng);

        let mp2 = MulProof::create(transcript, rng, &z3, &z2, &c9, &c8, &c10);

        // Proof of c11
        let z5 = z4 * z4;
        let c11 = PedersenComm::new(z5, rng);
        let mp3 = MulProof::create(transcript, rng, &z4, &z4, &c10, &c10, &c11);

        // Proof of c13.
        let z6 = <P as PedersenConfig>::from_ob_to_sf(a.x - t.x);
        let c12 = &c1 - &c5;

        let z7 = z4 * z6; // z4 = b.y - a.y / (b.x - a.x), z6 = (a.x - t.x)
        let c13 = PedersenComm::new(z7, rng);

        let mp4 = MulProof::create(transcript, rng, &z4, &z6, &c10, &c12, &c13);

        // And now the remaining equality proofs.
        let c14 = &c5 + &c1 + &c3;
        let eq1 = EqualityProof::create(transcript, rng, &c14, &c11);

        // This is the corrected one.
        let c15 = &c6 + &c2;
        let eq2 = EqualityProof::create(transcript, rng, &c13, &c15);

        Self {
            c1: c1.comm,
            c2: c2.comm,
            c3: c3.comm,
            c4: c4.comm,
            c5: c5.comm,
            c6: c6.comm,
            c8: c8.comm,
            c10: c10.comm,
            c11: c11.comm,
            c13: c13.comm,
            mp1,
            mp2,
            mp3,
            mp4,
            e1: eq1,
            e2: eq2,
        }
    }

    /// verify. This function verifies that `self` is a valid elliptic curve addition
    /// proof. This function returns true if the proof is valid and false otherwise.
    /// # Arguments
    /// *`self` - the proof object.
    /// *`transcript` - the transcript object that is used.
    pub fn verify(&self, transcript: &mut Transcript) -> bool {
        // This function just needs to verify that everything else works as it should.
        Self::make_transcript(
            transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6,
        );

        // Check that the multiplication proof holds for proving that c7 * c8 == 1
        // We recover c7 as c3 - c1
        let c7 = (self.c3.into_group() - self.c1).into_affine();

        // Now we verify that c8 * c7 is a commitment to 1.
        // N.B We use the same fixed commitment to 1 as above.
        let commit_one = PedersenComm {
            comm: <P as SWCurveConfig>::GENERATOR,
            r: <P as CurveConfig>::ScalarField::ZERO,
        };
        let first = self.mp1.verify(transcript, &c7, &self.c8, &commit_one.comm);

        // Proof of c10 = c9 * c10.
        // We recover c9 as c4 - c2.
        let c9 = (self.c4.into_group() - self.c2).into_affine();
        let second = self.mp2.verify(transcript, &c9, &self.c8, &self.c10);

        // Proof of c11 = c10*c10
        let third = self.mp3.verify(transcript, &self.c10, &self.c10, &self.c11);

        // Proof of c13 = c10 * c12.
        // We recover c12 as c1 - c5
        let c12 = (self.c1.into_group() - self.c5).into_affine();
        let fourth = self.mp4.verify(transcript, &self.c10, &c12, &self.c13);

        // Verify that c5 + c1 + c3 == c11
        let c14 = (self.c5 + self.c1 + self.c3).into_affine();
        let fifth = self.e1.verify(transcript, &c14, &self.c11);

        // Verify that c13 == c6 + c2.
        let c15 = (self.c6 + self.c2).into_affine();
        let sixth = self.e2.verify(transcript, &self.c13, &c15);
        first && second && third && fourth && fifth && sixth
    }
}
