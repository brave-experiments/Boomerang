use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveGroup,
};

use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};

pub trait PedersenConfig : SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;
}

pub struct PedersenComm<P: PedersenConfig> {
    pub comm: sw::Affine<P>,
    pub r: <P as CurveConfig>::ScalarField,    
}

impl<P: PedersenConfig> PedersenComm<P> {    
    pub fn new<T: RngCore + CryptoRng> (x: <P as CurveConfig>::ScalarField, rng: &mut T) -> Self {
        let x_r = <P as CurveConfig>::ScalarField::rand(rng);
        let x_p = <P as SWCurveConfig>::GENERATOR.mul(x) + P::GENERATOR2.mul(x_r);
        Self {comm: x_p.into_affine(), r: x_r }
    }
}

