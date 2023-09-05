use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveGroup,
};

use ark_std::{UniformRand, ops::Mul};
use rand::{RngCore, CryptoRng};
use num_bigint;


pub trait PedersenConfig : SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;

    /// The curve type that maps to this PedersenConfig.
    /// For example, for T256 it would be P256.
    type OCurve : CurveConfig;
}

pub struct PedersenComm<P: PedersenConfig> {
    pub comm: sw::Affine<P>,
    pub r: <P as CurveConfig>::ScalarField,    
}


impl<P: PedersenConfig> PedersenComm<P> {    
    pub fn new<T: RngCore + CryptoRng>(x: <P as CurveConfig>::ScalarField, rng: &mut T) -> Self {
        let x_r = <P as CurveConfig>::ScalarField::rand(rng);
        let x_p = <P as SWCurveConfig>::GENERATOR.mul(x) + P::GENERATOR2.mul(x_r);
        Self {comm: x_p.into_affine(), r: x_r }
    }

    pub fn new_from_ocurve<T: RngCore + CryptoRng>(x : <<P as PedersenConfig>::OCurve as CurveConfig>::ScalarField, rng: &mut T) -> Self {
        let x_r = <P as CurveConfig>::ScalarField::rand(rng);

        // To make this work for types that don't necessarily map 1:1, we need to convert x into a
        // big_uint first and then into the type in our field. This is annoying, but hopefully not too
        // painful long term. 
        let x_bt : num_bigint::BigUint = x.into();
        let x_c = <P as CurveConfig>::ScalarField::from(x_bt);
        
        let x_p = <P as SWCurveConfig>::GENERATOR.mul(x_c) + P::GENERATOR2.mul(x_r);
        Self { comm: x_p.into_affine(), r: x_r }
    }
}

