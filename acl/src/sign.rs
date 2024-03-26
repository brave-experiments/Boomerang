//!
//! Module containing the definition of the private key container
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::{config::ACLConfig, config::KeyPair, config::StateSignatureComm};
use ark_serialize::CanonicalSerialize;
use ark_std::{ops::Mul, UniformRand};
use pedersen::pedersen_config::PedersenComm;
use pedersen::pedersen_config::PedersenConfig;

/// SigComm. This struct acts as a container for the first message (the commitment) of the Signature.
pub struct SigComm<A: ACLConfig> {
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
    /// create_message_one. This function creates the first signature message.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn create_message_one<T: RngCore + CryptoRng>(
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

        Self { rand, a, a1, a2 }
    }
}
