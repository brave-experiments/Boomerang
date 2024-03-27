//!
//! Module containing the definition of the singing side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
    CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::verify::SigChall;
use crate::{config::ACLConfig, config::KeyPair};
use ark_std::{ops::Mul, UniformRand};
use pedersen::pedersen_config::PedersenComm;

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
    /// respond. This function creates the thrid signature message.
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
