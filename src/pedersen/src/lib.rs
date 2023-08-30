#![forbid(unsafe_code)]

use ark_ec::{
    CurveConfig,
    CurveGroup, 
    short_weierstrass::{self as sw, SWCurveConfig},
};

use ark_std::{UniformRand, ops::Mul};

use rand::RngCore;

pub trait PedersenConfig : CurveConfig + SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;
}

pub struct PedersenComm<P: PedersenConfig> {
    pub x_comm: sw::Affine<P>,
    pub x_r: <P as CurveConfig>::ScalarField,
    pub y_comm: sw::Affine<P>,
    pub y_r: <P as CurveConfig>::ScalarField
}

impl<P: PedersenConfig> PedersenComm<P> {    
    pub fn new (x: <P as CurveConfig>::ScalarField, y: <P as CurveConfig>::ScalarField, rng: &mut dyn RngCore) -> Self {
        let x_r = <P as CurveConfig>::ScalarField::rand(rng);
        let y_r = <P as CurveConfig>::ScalarField::rand(rng);

        let x_p = <P as SWCurveConfig>::GENERATOR.mul(x) + P::GENERATOR2.mul(x_r);
        let y_p = <P as SWCurveConfig>::GENERATOR.mul(y) + P::GENERATOR2.mul(y_r);
        
        Self {x_comm: x_p.into_affine(), x_r: x_r, y_comm: y_p.into_affine(), y_r: y_r}
    }
}



