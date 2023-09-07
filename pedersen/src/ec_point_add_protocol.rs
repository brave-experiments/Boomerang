//! Defines a protocol for proof of elliptic curve point addition.
//! Namely, this protocol proves that A + B = T, for A, B, T \in E(F_{q}).
//! This protocol is the same as the protocol described in Theorem 4 of the paper.

use ark_ec::CurveConfig;
use merlin::Transcript;

use ark_ff::fields::Field;
use ark_serialize::CanonicalSerialize;

use rand::{CryptoRng, RngCore};

use crate::{
    mul_protocol::MulProof, opening_protocol::OpeningProof, pedersen_config::PedersenComm,
    pedersen_config::PedersenConfig, transcript::ECPointAdditionTranscript,
};

pub struct ECPointAddProof<P: PedersenConfig> {
    /// c1: the commitment to a_x.
    pub c1: PedersenComm<P>,
    /// c2: the commitment to a_y.
    pub c2: PedersenComm<P>,
    /// c3: the commitment to b_x.
    pub c3: PedersenComm<P>,
    /// c4: the commitment to b_y.
    pub c4: PedersenComm<P>,
    /// c5: the commitment to t_x.
    pub c5: PedersenComm<P>,
    /// c6: the commitment to t_y.
    pub c6: PedersenComm<P>,

    /// c7: the commitment to tau = (b_y - a_y)/(b_x - a_x)
    pub c7: PedersenComm<P>,

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
    fn make_transcript(
        transcript: &mut Transcript,
        c1: &PedersenComm<P>,
        c2: &PedersenComm<P>,
        c3: &PedersenComm<P>,
        c4: &PedersenComm<P>,
        c5: &PedersenComm<P>,
        c6: &PedersenComm<P>,
        c7: &PedersenComm<P>,
    ) {
        // This function just builds the transcript for both the create and verify functions.
        // N.B Because of how we define the serialisation API to handle different numbers,
        // we use a temporary buffer here.
        ECPointAdditionTranscript::domain_sep(transcript);

        let mut compressed_bytes = Vec::new();
        c1.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C1", &compressed_bytes[..]);

        c2.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C2", &compressed_bytes[..]);

        c3.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C3", &compressed_bytes[..]);

        c4.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C4", &compressed_bytes[..]);

        c5.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C5", &compressed_bytes[..]);

        c6.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C6", &compressed_bytes[..]);

        c7.comm.serialize_compressed(&mut compressed_bytes).unwrap();
        ECPointAdditionTranscript::append_point(transcript, b"C7", &compressed_bytes[..]);
    }

    fn make_commitment<T: RngCore + CryptoRng>(
        val: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        rng: &mut T,
    ) -> PedersenComm<P> {
        let val_p = <P as PedersenConfig>::from_ob_to_sf(val);
        PedersenComm::new(val_p, rng)
    }

    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        a_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        a_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        b_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        b_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        t_x: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        t_y: <<P as PedersenConfig>::OCurve as CurveConfig>::BaseField,
    ) -> Self {
        // Commit to each of the co-ordinate pairs.
        let c1 = Self::make_commitment(a_x, rng);
        let c2 = Self::make_commitment(a_y, rng);
        let c3 = Self::make_commitment(b_x, rng);
        let c4 = Self::make_commitment(b_y, rng);
        let c5 = Self::make_commitment(t_x, rng);
        let c6 = Self::make_commitment(t_y, rng);

        // c7 is the commitment to tau, the gradient.
        let tau = (b_y - a_y) * ((b_x - a_x).inverse().unwrap());
        let taua = <P as PedersenConfig>::from_ob_to_sf(tau);
        let c7 = PedersenComm::new(taua, rng);

        // Now commit to all of them.
        Self::make_transcript(transcript, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

        // And now we simply invoke each of the sub-protocols.
        // TODO: shouldn't all of these proofs be done in parallel? Meaning using one long challenge..
        let z1 = &c3 - &c1;
        let z2 = &c4 - &c2;
        let x1 = <P as PedersenConfig>::from_ob_to_sf(b_x - a_x);
        let mp1 = MulProof::create(transcript, rng, &x1, &taua, &z1, &c7, &z2);

        let z4 = &c1 + &c3 + &c5;
        let mp2 = MulProof::create(transcript, rng, &taua, &taua, &c7, &c7, &z4);
        assert!(mp2.alpha.is_on_curve());
        assert!(mp2.beta.is_on_curve());
        assert!(mp2.delta.is_on_curve());

        let x3 = <P as PedersenConfig>::from_ob_to_sf(a_x - t_x);

        let z5 = &c1 - &c5;
        let z6 = &c2 + &c6;
        let mp3 = MulProof::create(transcript, rng, &taua, &x3, &c7, &z5, &z6);

        let op = OpeningProof::create(transcript, rng, &taua, &c7); // TODO: shouldn't this be c2?

        // And now we just return.
        Self {
            c1: c1,
            c2: c2,
            c3: c3,
            c4: c4,
            c5: c5,
            c6: c6,
            c7: c7,
            mp1: mp1,
            mp2: mp2,
            mp3: mp3,
            op: op,
        }
    }

    pub fn verify(&self, transcript: &mut Transcript) -> bool {
        Self::make_transcript(
            transcript, &self.c1, &self.c2, &self.c3, &self.c4, &self.c5, &self.c6, &self.c7,
        );

        let z1 = &self.c3 - &self.c1;
        let z2 = &self.c7;
        let z3 = &self.c4 - &self.c2;
        let z4 = &self.c1 + &self.c3 + &self.c5;
        let z5 = &self.c1 - &self.c5;
        let z6 = &self.c2 + &self.c6;

        self.mp1.verify(transcript, &z1, &z2, &z3)
            && self.mp2.verify(transcript, &self.c7, &self.c7, &z4)
            && self.mp3.verify(transcript, &z2, &z5, &z6)
            && self.op.verify(transcript, &self.c7)
    }
}
