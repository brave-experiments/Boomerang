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

    c: <A as CurveConfig>::ScalarField,
    u: <A as CurveConfig>::ScalarField,
    r1: <A as CurveConfig>::ScalarField,
    r2: <A as CurveConfig>::ScalarField,
}

// We need to implement these manually for generic structs.
impl<A: ACLConfig> Copy for SigComm<A> {}
impl<A: ACLConfig> Clone for SigComm<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: ACLConfig> SigComm<A> {
    /// commit. This function creates the first signature message.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn commit<T: RngCore + CryptoRng>(
        keys: KeyPair<A>,
        rng: &mut T,
        comm: sw::Affine<A>,
    ) -> SigComm<A> {
        let rand = <A as CurveConfig>::ScalarField::rand(rng);
        let u = <A as CurveConfig>::ScalarField::rand(rng);
        let r1 = <A as CurveConfig>::ScalarField::rand(rng);
        let r2 = <A as CurveConfig>::ScalarField::rand(rng);
        let c = <A as CurveConfig>::ScalarField::rand(rng);

        let z1 = (A::GENERATOR.mul(rand) + comm).into_affine();
        let z2 = (keys.tag_key - z1).into_affine();
        let a = (A::GENERATOR.mul(u)).into_affine();
        let a1 = (A::GENERATOR.mul(r1) + z1.mul(c)).into_affine();
        let a2 = (A::GENERATOR2.mul(r2) + z2.mul(c)).into_affine();

        Self {
            comms: comm,
            rand,
            a,
            a1,
            a2,
            c,
            u,
            r1,
            r2,
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
    pub fn respond(keys: KeyPair<A>, comm_m: SigComm<A>, chall_m: SigChall<A>) -> SigResp<A> {
        let c = chall_m.e - comm_m.c;
        let r = comm_m.u - c * keys.signing_key();

        Self {
            c,
            c1: comm_m.c,
            r,
            r1: comm_m.r1,
            r2: comm_m.r2,
        }
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

    pub fn verify(pub_key: sw::Affine<A>, tag_key: sw::Affine<A>, sig_m: SigSign<A>) -> bool {
        let z2 = sig_m.sigma.zeta - sig_m.sigma.zeta1;
        let tmp1 =
            (A::GENERATOR.mul(sig_m.sigma.rho) + pub_key.mul(sig_m.sigma.omega)).into_affine();
        let tmp2 = (A::GENERATOR.mul(sig_m.sigma.rho1) + sig_m.sigma.zeta1.mul(sig_m.sigma.omega1))
            .into_affine();
        let tmp3 = (A::GENERATOR2.mul(sig_m.sigma.rho2) + z2.mul(sig_m.sigma.omega1)).into_affine();
        let tmp4 =
            (tag_key.mul(sig_m.sigma.v) + sig_m.sigma.zeta.mul(sig_m.sigma.omega1)).into_affine();

        let label = b"Chall ACL";
        let mut transcript_v = Transcript::new(label);
        Self::make_transcript(
            &mut transcript_v,
            &sig_m.sigma.zeta,
            &sig_m.sigma.zeta1,
            &tmp1,
            &tmp2,
            &tmp3,
            &tmp4,
        );

        let mut buf = [0u8; 64];
        let _ = &transcript_v.challenge_bytes(b"chall", &mut buf);

        let epsilon: <A as CurveConfig>::ScalarField =
            <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();

        let e = sig_m.sigma.omega + sig_m.sigma.omega1;

        return e == epsilon;
    }
}

/// SigProof. This struct acts as a container for the proof of signature.
pub struct SigProof<A: ACLConfig> {
    /// b_gamma: the first message value.
    pub b_gamma: sw::Affine<A>,
    /// p1: the first proof.
    pub pi1: <A as CurveConfig>::ScalarField,
    /// p2: the second proof.
    pub pi2: <A as CurveConfig>::ScalarField,
    /// h_vec: the commitment to the sub values.
    pub h_vec: Vec<sw::Affine<A>>,
}

impl<A: ACLConfig> SigProof<A> {
    pub fn make_transcript(transcript: &mut Transcript, c1: &sw::Affine<A>, c2: &sw::Affine<A>) {
        transcript.append_message(b"dom-sep", b"acl-challenge-zk");

        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c1", &compressed_bytes[..]);

        c2.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c2", &compressed_bytes[..]);
    }

    pub fn prove<T: RngCore + CryptoRng>(
        rng: &mut T,
        tag_key: sw::Affine<A>,
        sig_m: SigSign<A>,
        vals: Vec<<A as CurveConfig>::ScalarField>,
        gens: Vec<sw::Affine<A>>,
        vals_sub: Vec<<A as CurveConfig>::ScalarField>,
    ) -> SigProof<A> {
        let b_gamma = (A::GENERATOR.mul(sig_m.opening.gamma)).into_affine();

        let mut h_vec: Vec<sw::Affine<A>> = vec![];
        for i in 1..vals.len() {
            let h = (gens[i].mul(sig_m.opening.gamma)).into_affine();
            h_vec.push(h);
        }

        // Equality proofs of zeta = b_gamma
        let r = <A as CurveConfig>::ScalarField::rand(rng);
        let t1 = (tag_key.mul(r)).into_affine();
        let t2 = (A::GENERATOR.mul(r)).into_affine();

        let label = b"Chall ACLZK";
        let mut transcript_v = Transcript::new(label);
        Self::make_transcript(&mut transcript_v, &t1, &t2);

        let mut buf = [0u8; 64];
        let _ = &transcript_v.challenge_bytes(b"challzk", &mut buf);

        let ch: <A as CurveConfig>::ScalarField =
            <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();

        let pi1 = r + sig_m.opening.gamma * ch;

        // Equality proofs of zeta = h_vec -> TODO

        // Compute partial commitment

        let mut total: sw::Affine<A> = sw::Affine::identity();
        for i in 1..vals_sub.len() {
            total = (total + (gens[i].mul(vals_sub[i] + sig_m.opening.gamma))).into();
        }

        let zeta1_o = sig_m.sigma.zeta1 - total;

        let pi2 = r + sig_m.opening.gamma * ch; // for the moment

        Self {
            b_gamma,
            pi1,
            pi2,
            h_vec,
        }
    }
}
