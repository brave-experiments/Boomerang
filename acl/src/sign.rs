//!
//! Module containing the definition of the singing side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
    CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::verify::{SigChall, SigSign};
use crate::{config::ACLConfig, config::KeyPair};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand};
use merlin::Transcript;
use pedersen::pedersen_config::PedersenComm;
use std::marker::PhantomData;

/// SigComm. This struct acts as a container for the first message (the commitment) of the Signature.
pub struct SigComm<A: ACLConfig> {
    /// comms: the multi-commitment to chosen values.
    pub comms: sw::Affine<A>,
    /// rand: the first message value.
    pub rand: <A as CurveConfig>::ScalarField,
    /// a: the second message value.
    pub a: sw::Affine<A>,
    /// a1: the third message value.
    pub a1: sw::Affine<A>,
    /// a2: the fourth message value.
    pub a2: sw::Affine<A>,
}

impl<A: ACLConfig> SigComm<A> {
    /// commit. This function creates the first signature message.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn commit<T: RngCore + CryptoRng>(
        keys: KeyPair<A>,
        rng: &mut T,
        vals: Vec<<A as CurveConfig>::ScalarField>,
    ) -> SigComm<A> {
        let comms = PedersenComm::new_multi(vals, rng);

        let rand = <A as CurveConfig>::ScalarField::rand(rng);
        let u = <A as CurveConfig>::ScalarField::rand(rng);
        let r1 = <A as CurveConfig>::ScalarField::rand(rng);
        let r2 = <A as CurveConfig>::ScalarField::rand(rng);
        let c = <A as CurveConfig>::ScalarField::rand(rng);

        let z1 = (A::GENERATOR.mul(rand) + comms.commitment()).into_affine();
        let z2 = (keys.tag_key - z1).into_affine();
        let a = (A::GENERATOR.mul(u)).into_affine();
        let a1 = (A::GENERATOR.mul(r1) + z1.mul(c)).into_affine();
        let a2 = (A::GENERATOR.mul(r2) + z2.mul(c)).into_affine();

        Self {
            comms: comms.commitment(),
            rand,
            a,
            a1,
            a2,
        }
    }
}

/// SigResp. This struct acts as a container for the third message (the response) of the Signature.
pub struct SigResp<A: ACLConfig> {
    /// c: the first message value.
    pub c: <A as CurveConfig>::ScalarField,
    /// c1: the second message value.
    pub c1: <A as CurveConfig>::ScalarField,
    /// r: the second message value.
    pub r: <A as CurveConfig>::ScalarField,
    /// r1: the second message value.
    pub r1: <A as CurveConfig>::ScalarField,
    /// r2: the second message value.
    pub r2: <A as CurveConfig>::ScalarField,
}

impl<A: ACLConfig> SigResp<A> {
    /// respond. This function creates the third signature message.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn respond(
        keys: KeyPair<A>,
        c1: <A as CurveConfig>::ScalarField,
        u: <A as CurveConfig>::ScalarField,
        r1: <A as CurveConfig>::ScalarField,
        r2: <A as CurveConfig>::ScalarField,
        chall_m: SigChall<A>,
    ) -> SigResp<A> {
        let c = chall_m.e - c1;
        let r = u - c * keys.signing_key();

        Self { c, c1, r, r1, r2 }
    }
}

pub struct SigVerify<A: ACLConfig> {
    _marker: PhantomData<A>,
}

impl<A: ACLConfig> SigVerify<A> {
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
        transcript.append_message(b"dom-sep", b"acl-sign");

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

    pub fn verify(
        pub_key: sw::Affine<A>,
        tag_key: sw::Affine<A>,
        sig_m: SigSign<A>,
        zeta2: sw::Affine<A>,
    ) -> bool {
        let tmp1 =
            (A::GENERATOR.mul(sig_m.sigma.rho) + pub_key.mul(sig_m.sigma.omega)).into_affine();
        let tmp2 = (A::GENERATOR.mul(sig_m.sigma.rho1) + sig_m.sigma.zeta1.mul(sig_m.sigma.omega1))
            .into_affine();
        let tmp3 =
            (A::GENERATOR2.mul(sig_m.sigma.rho2) + zeta2.mul(sig_m.sigma.omega1)).into_affine();
        let tmp4 =
            (tag_key.mul(sig_m.sigma.v) + sig_m.sigma.zeta.mul(sig_m.sigma.omega1)).into_affine();

        let label = b"Sign ACL";
        let mut transcript_v = Transcript::new(label);
        Self::make_transcript(
            &mut transcript_v,
            &sig_m.sigma.zeta,
            &sig_m.sigma.zeta1,
            &zeta2,
            &tmp1,
            &tmp2,
            &tmp3,
            &tmp4,
        );

        let mut buf = [0u8; 64];
        let _ = &transcript_v.challenge_bytes(b"sig", &mut buf);

        let epsilon: <A as CurveConfig>::ScalarField =
            <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();

        let e = sig_m.sigma.omega + sig_m.sigma.omega1;

        return e == epsilon;
    }
}
