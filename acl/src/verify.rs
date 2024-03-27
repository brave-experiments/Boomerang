//!
//! Module containing the definition of the verification side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::config::ACLConfig;
use crate::sign::SigComm;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use ark_std::{ops::Mul, UniformRand};
use merlin::Transcript;

pub const CHALLENGE_SIZE: usize = 64;
/// SigChall. This struct acts as a container for the second message (the challenge) of the Signature.
pub struct SigChall<A: ACLConfig> {
    /// e: the first message value.
    pub e: <A as CurveConfig>::ScalarField,
}

impl<A: ACLConfig> SigChall<A> {
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<A>,
        c2: &sw::Affine<A>,
        c3: &sw::Affine<A>,
        c4: &sw::Affine<A>,
        c5: &sw::Affine<A>,
        c6: &sw::Affine<A>,
        c7: &sw::Affine<A>,
    ) {
        transcript.append_message(b"dom-sep", b"acl-challenge");

        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c2", &compressed_bytes[..]);

        c3.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c3", &compressed_bytes[..]);

        c4.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c4", &compressed_bytes[..]);

        c5.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c5", &compressed_bytes[..]);

        c6.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c6", &compressed_bytes[..]);

        c7.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c7", &compressed_bytes[..]);
    }

    /// challenge. This function creates the second signature message.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn challenge<T: RngCore + CryptoRng>(
        tag_key: sw::Affine<A>,
        pub_key: sw::Affine<A>,
        rng: &mut T,
        comm_m: SigComm<A>,
    ) -> SigChall<A> {
        if comm_m.rand.is_zero()
            || !comm_m.a.is_on_curve()
            || !comm_m.a1.is_on_curve()
            || !comm_m.a2.is_on_curve()
        {
            panic!("Failed to create signature challenge: params are incorrect");
        } else {
            let z1 = (A::GENERATOR.mul(comm_m.rand) + comm_m.comms).into_affine();

            let gamma = <A as CurveConfig>::ScalarField::rand(rng);
            let tau = <A as CurveConfig>::ScalarField::rand(rng);

            let zeta = (tag_key.mul(gamma)).into_affine();
            let zeta1 = (z1.mul(gamma)).into_affine();
            let zeta2 = (zeta - zeta1).into_affine();
            let mu = (tag_key.mul(tau)).into_affine();

            let t1 = <A as CurveConfig>::ScalarField::rand(rng);
            let t2 = <A as CurveConfig>::ScalarField::rand(rng);
            let t3 = <A as CurveConfig>::ScalarField::rand(rng);
            let t4 = <A as CurveConfig>::ScalarField::rand(rng);
            let t5 = <A as CurveConfig>::ScalarField::rand(rng);

            let alpha = (comm_m.a + A::GENERATOR.mul(t1) + pub_key.mul(t2)).into_affine();
            let alpha1 =
                (comm_m.a1.mul(gamma) + A::GENERATOR.mul(t3) + zeta1.mul(t4)).into_affine();
            let alpha2 =
                (comm_m.a2.mul(gamma) + A::GENERATOR2.mul(t5) + zeta2.mul(t4)).into_affine();

            let label = b"Chall ACL";
            let mut transcript_v = Transcript::new(label);
            Self::make_transcript(
                &mut transcript_v,
                &zeta,
                &zeta1,
                &zeta2,
                &alpha,
                &alpha1,
                &alpha2,
                &mu,
            );

            let mut buf = [0u8; CHALLENGE_SIZE];
            let _ = &transcript_v.challenge_bytes(b"chall", &mut buf);

            let epsilon: <A as CurveConfig>::ScalarField =
                <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();
            let e = epsilon - t2 - t4;

            Self { e }
        }
    }
}
