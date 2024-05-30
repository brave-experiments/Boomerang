//!
//! Module containing the definition of the signing side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
    CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::config::ACLConfig;
use crate::verify::{SigComm, SigResp};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand, Zero};
use merlin::Transcript;
use std::default::Default;

pub const CHALLENGE_SIZE: usize = 64;

/// SigChall. This struct acts as a container for the second message (the challenge) of the Signature.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
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

impl<A: ACLConfig> Clone for SigChall<A> {
    fn clone(&self) -> Self {
        SigChall {
            e: self.e,
            zeta: self.zeta,
            zeta1: self.zeta1,
            zeta2: self.zeta2,
            gamma: self.gamma,
            rand: self.rand,
            tau: self.tau,
            t1: self.t1,
            t2: self.t2,
            t3: self.t3,
            t4: self.t4,
            t5: self.t5,
        }
    }
}

impl<P: ACLConfig> Default for SigChall<P> {
    fn default() -> Self {
        Self {
            e: <P as CurveConfig>::ScalarField::zero(), // Default value for `e`
            zeta: sw::Affine::<P>::default(),           // Default value for `zeta`
            zeta1: sw::Affine::<P>::default(),          // Default value for `zeta1`
            zeta2: sw::Affine::<P>::default(),          // Default value for `zeta2`
            gamma: <P as CurveConfig>::ScalarField::zero(), // Default value for `gamma`
            rand: <P as CurveConfig>::ScalarField::zero(), // Default value for `rand`
            tau: <P as CurveConfig>::ScalarField::zero(), // Default value for `tau`
            t1: <P as CurveConfig>::ScalarField::zero(), // Default value for `t1`
            t2: <P as CurveConfig>::ScalarField::zero(), // Default value for `t2`
            t3: <P as CurveConfig>::ScalarField::zero(), // Default value for `t3`
            t4: <P as CurveConfig>::ScalarField::zero(), // Default value for `t4`
            t5: <P as CurveConfig>::ScalarField::zero(), // Default value for `t5`
        }
    }
}

impl<A: ACLConfig> SigChall<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<A>,
        c2: &sw::Affine<A>,
        c3: &sw::Affine<A>,
        c4: &sw::Affine<A>,
        c5: &sw::Affine<A>,
        c6: &sw::Affine<A>,
        message: &str,
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

        transcript.append_message(b"message", message.as_bytes());
    }

    /// challenge. This function creates the second signature message.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn challenge<T: RngCore + CryptoRng>(
        tag_key: sw::Affine<A>,
        pub_key: sw::Affine<A>,
        rng: &mut T,
        comm_m: SigComm<A>,
        message: &str,
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
                &mu,
                message,
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
#[derive(CanonicalSerialize, CanonicalDeserialize)]
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

impl<A: ACLConfig> Clone for Signature<A> {
    fn clone(&self) -> Self {
        Self {
            zeta: self.zeta,
            zeta1: self.zeta1,
            rho: self.rho,
            omega: self.omega,
            rho1: self.rho1,
            rho2: self.rho2,
            v: self.v,
            omega1: self.omega1,
        }
    }
}

/// Opening. This struct acts as a container for the opening.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Opening<A: ACLConfig> {
    /// gamma: the first message value.
    pub gamma: <A as CurveConfig>::ScalarField,
    /// rand: the second message value.
    pub rand: <A as CurveConfig>::ScalarField,
}

impl<A: ACLConfig> Clone for Opening<A> {
    fn clone(&self) -> Self {
        Self {
            gamma: self.gamma,
            rand: self.rand,
        }
    }
}

/// SigSign. This struct acts as a container for the fourth message (the signature) of the Signature.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SigSign<A: ACLConfig> {
    /// sigma: the signature itself.
    pub sigma: Signature<A>,
    /// opening: the opening values.
    opening: Opening<A>,
}

impl<A: ACLConfig> Clone for SigSign<A> {
    fn clone(&self) -> Self {
        Self {
            sigma: self.sigma.clone(),
            opening: self.opening.clone(),
        }
    }
}

impl<A: ACLConfig> SigSign<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn make_transcript(
        transcript: &mut Transcript,
        c1: &sw::Affine<A>,
        c2: &sw::Affine<A>,
        c3: &sw::Affine<A>,
        c4: &sw::Affine<A>,
        c5: &sw::Affine<A>,
        c6: &sw::Affine<A>,
        message: &str,
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

        transcript.append_message(b"message", message.as_bytes());
    }

    pub fn sign(
        pub_key: sw::Affine<A>,
        tag_key: sw::Affine<A>,
        chall_m: &SigChall<A>,
        resp_m: &SigResp<A>,
        message: &str,
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
            message,
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
                zeta: chall_m.zeta,
                zeta1: chall_m.zeta1,
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

pub struct SubVals<A: ACLConfig> {
    pub vals_sub: Vec<<A as CurveConfig>::ScalarField>,
    pub pos: Vec<usize>,
}

/// DLogProof. This struct acts as a container for the opening proof.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigProofD<A: ACLConfig> {
    /// t2: the second proof.
    pub t1: sw::Affine<A>,
    /// t2: the second proof.
    pub t2: sw::Affine<A>,
    /// b_gamma: the first message value.
    pub a1: <A as CurveConfig>::ScalarField,
}

/// OpeningProof. This struct acts as a container for the opening proof.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigProofO<A: ACLConfig> {
    /// t2: the second proof.
    pub t3: sw::Affine<A>,
    /// t2: the second proof.
    pub a3: <A as CurveConfig>::ScalarField,
    /// b_gamma: the first message value.
    pub a4: <A as CurveConfig>::ScalarField,
}

/// SigProof. This struct acts as a container for the proof of signature.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigProof<A: ACLConfig> {
    /// b_gamma: the first message value.
    pub b_gamma: sw::Affine<A>,
    /// p1: the first proof.
    pub pi1: SigProofD<A>,
    /// p2: the second proof.
    pub pi2: SigProofO<A>,
    /// p3: the third proof.
    pub pi3: Vec<SigProofD<A>>,
    /// h_vec: the commitment to the sub values.
    pub h_vec: Vec<sw::Affine<A>>,
    /// val: the first message value.
    pub val: sw::Affine<A>,
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

    pub fn make_transcript_one(transcript: &mut Transcript, c1: &sw::Affine<A>) {
        transcript.append_message(b"dom-sep", b"acl-challenge-zk2");

        let mut compressed_bytes = Vec::new();
        c1.serialize_compressed(&mut compressed_bytes).unwrap();
        transcript.append_message(b"c1", &compressed_bytes[..]);
    }

    pub fn prove<T: RngCore + CryptoRng>(
        rng: &mut T,
        tag_key: sw::Affine<A>,
        sig_m: &SigSign<A>,
        vals: &[<A as CurveConfig>::ScalarField],
        gens: &[sw::Affine<A>],
        comm_r: <A as CurveConfig>::ScalarField,
    ) -> SigProof<A> {
        let b_gamma = (A::GENERATOR.mul(sig_m.opening.gamma)).into_affine();

        let mut h_vec: Vec<sw::Affine<A>> = vec![];
        for item in gens.iter().take(vals.len()).skip(1) {
            let h = (item.mul(sig_m.opening.gamma)).into_affine();
            h_vec.push(h);
        }

        // Equality proof of zeta = b_gamma
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

        let a1 = r + sig_m.opening.gamma * ch;

        let pi1 = SigProofD { t1, t2, a1 };

        // Equality proofs of zeta = h_vec
        let pi_hvec: Vec<SigProofD<A>> = gens
            .iter()
            .take(vals.len())
            .skip(1)
            .map(|&item| {
                let r = <A as CurveConfig>::ScalarField::rand(rng);
                let t1 = (tag_key.mul(r)).into_affine();
                let t2 = (item.mul(sig_m.opening.gamma)).into_affine();

                let label3 = b"Chall ACLZK3";
                let mut transcript_v = Transcript::new(label3);
                Self::make_transcript(&mut transcript_v, &t1, &t2);

                let mut buf3 = [0u8; 64];
                let _ = &transcript_v.challenge_bytes(b"challzk3", &mut buf3);

                let ch: <A as CurveConfig>::ScalarField =
                    <A as CurveConfig>::ScalarField::deserialize_compressed(&buf[..]).unwrap();

                let a1 = r + sig_m.opening.gamma * ch;

                // Opening proof `pi`
                SigProofD { t1, t2, a1 }
            })
            .collect();

        // Compute partial commitment
        //let mut total: sw::Affine<A> = sw::Affine::identity();
        //for i in 0..vals_sub_s.vals_sub.len() {
        //    total = (total
        //        + (gens[vals_sub_s.pos[i]].mul(vals_sub_s.vals_sub[i] + sig_m.opening.gamma)))
        //    .into();
        //}

        //let _ = sig_m.sigma.zeta1 - total;

        // For our cases, we will always prove knowledge of all signed committed values,
        // but this is not for all cases.
        // Hence, we only need to prove knowledge of g^rand and h^r

        let alpha1 = <A as CurveConfig>::ScalarField::rand(rng);
        let alpha2 = <A as CurveConfig>::ScalarField::rand(rng);
        let t3 = (A::GENERATOR.mul(alpha1) + A::GENERATOR2.mul(alpha2)).into_affine();

        let label2 = b"Chall ACLZK2";
        let mut transcript_v = Transcript::new(label2);
        Self::make_transcript_one(&mut transcript_v, &t3);

        let mut buf2 = [0u8; 64];
        let _ = &transcript_v.challenge_bytes(b"challzk2", &mut buf2);

        let ch2: <A as CurveConfig>::ScalarField =
            <A as CurveConfig>::ScalarField::deserialize_compressed(&buf2[..]).unwrap();

        let a3 = alpha1 + sig_m.opening.rand * ch2; // proof g^rand
        let a4 = alpha2 + comm_r * ch2; // proof h^r

        let pi2 = SigProofO { t3, a3, a4 };

        let val = (A::GENERATOR.mul(sig_m.opening.rand) + A::GENERATOR2.mul(comm_r)).into_affine();

        Self {
            b_gamma,
            pi1,
            pi2,
            pi3: pi_hvec,
            h_vec,
            val,
        }
    }
}
