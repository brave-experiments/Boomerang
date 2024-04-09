//!
//! Module containing the definition of the verification side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
    CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::config::ACLConfig;
use crate::sign::{SigComm, SigResp};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand, Zero};
use merlin::Transcript;

pub const CHALLENGE_SIZE: usize = 64;

/// SigChall. This struct acts as a container for the second message (the challenge) of the Signature.
pub struct SigChall<A: ACLConfig> {
    /// e: the first message value.
    pub e: <A as CurveConfig>::ScalarField,

    zeta: sw::Affine<A>,
    zeta1: sw::Affine<A>,
    zeta2: sw::Affine<A>,
    gamma: <A as CurveConfig>::ScalarField,
    rand: <A as CurveConfig>::ScalarField,
    tau: <A as CurveConfig>::ScalarField,
    t1: <A as CurveConfig>::ScalarField,
    t2: <A as CurveConfig>::ScalarField,
    t3: <A as CurveConfig>::ScalarField,
    t4: <A as CurveConfig>::ScalarField,
    t5: <A as CurveConfig>::ScalarField,
}

// We need to implement these manually for generic structs.
impl<A: ACLConfig> Copy for SigChall<A> {}
impl<A: ACLConfig> Clone for SigChall<A> {
    fn clone(&self) -> Self {
        *self
    }
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
                &alpha,
                &alpha1,
                &alpha2,
                &mu, // TODO: add message
            );

            let mut buf = [0u8; CHALLENGE_SIZE];
            let _ = &transcript_v.challenge_bytes(b"chall", &mut buf);

            let epsilon: <A as CurveConfig>::ScalarField =
                <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();
            let e = epsilon - t2 - t4;

            Self {
                e,
                zeta,
                zeta1,
                zeta2,
                gamma,
                rand: comm_m.rand,
                tau,
                t1,
                t2,
                t3,
                t4,
                t5,
            }
        }
    }
}

/// Signature. This struct acts as a container for the signature.
pub struct Signature<A: ACLConfig> {
    /// e: the first message value.
    pub zeta: sw::Affine<A>,
    /// e: the first message value.
    pub zeta1: sw::Affine<A>,
    /// e: the first message value.
    pub rho: <A as CurveConfig>::ScalarField,
    /// omega: the first message value.
    pub omega: <A as CurveConfig>::ScalarField,
    /// rho1: the first message value.
    pub rho1: <A as CurveConfig>::ScalarField,
    /// rho2: the first message value.
    pub rho2: <A as CurveConfig>::ScalarField,
    /// v: the first message value.
    pub v: <A as CurveConfig>::ScalarField,
    /// omega1: the first message value.
    pub omega1: <A as CurveConfig>::ScalarField,
}

/// Opening. This struct acts as a container for the opening.
pub struct Opening<A: ACLConfig> {
    /// gamma: the first message value.
    pub gamma: <A as CurveConfig>::ScalarField,
    /// rand: the first message value.
    pub rand: <A as CurveConfig>::ScalarField,
}

/// SigSign. This struct acts as a container for the fourth message (the signature) of the Signature.
pub struct SigSign<A: ACLConfig> {
    /// sigma: the first message value.
    pub sigma: Signature<A>,
    /// opening: the first message value.
    pub opening: Opening<A>,
}

impl<A: ACLConfig> SigSign<A> {
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<A>,
        c2: &sw::Affine<A>,
        c3: &sw::Affine<A>,
        c4: &sw::Affine<A>,
        c5: &sw::Affine<A>,
        c6: &sw::Affine<A>,
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
    }

    pub fn sign(
        pub_key: sw::Affine<A>,
        tag_key: sw::Affine<A>,
        chall_m: SigChall<A>,
        resp_m: SigResp<A>,
    ) -> SigSign<A> {
        let rho = resp_m.r + chall_m.t1;
        let omega = resp_m.c + chall_m.t2;
        let rho1 = chall_m.gamma * resp_m.r1 + chall_m.t3;
        let rho2 = chall_m.gamma * resp_m.r2 + chall_m.t5;
        let omega1 = resp_m.c1 + chall_m.t4;
        let v = chall_m.tau - omega1 * chall_m.gamma;

        let tmp1 = (A::GENERATOR.mul(rho) + pub_key.mul(omega)).into_affine();
        let tmp2 = (A::GENERATOR.mul(rho1) + chall_m.zeta1.mul(omega1)).into_affine();
        let tmp3 = (A::GENERATOR2.mul(rho2) + chall_m.zeta2.mul(omega1)).into_affine();
        let tmp4 = (tag_key.mul(v) + chall_m.zeta.mul(omega1)).into_affine();

        let label = b"Chall ACL";
        let mut transcript_v = Transcript::new(label);
        Self::make_transcript(
            &mut transcript_v,
            &chall_m.zeta,
            &chall_m.zeta1,
            &tmp1,
            &tmp2,
            &tmp3,
            &tmp4,
        );

        let mut buf = [0u8; CHALLENGE_SIZE];
        let _ = &transcript_v.challenge_bytes(b"chall", &mut buf);

        let epsilon: <A as CurveConfig>::ScalarField =
            <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();

        let e = omega + omega1;

        if e != epsilon {
            panic!("Failed to create a signature");
        } else {
            let sigma = Signature {
                zeta1: chall_m.zeta1,
                zeta: chall_m.zeta,
                rho,
                omega,
                rho1,
                rho2,
                v,
                omega1,
            };

            let opening = Opening {
                gamma: chall_m.gamma,
                rand: chall_m.rand,
            };

            Self { sigma, opening }
        }
    }
}
