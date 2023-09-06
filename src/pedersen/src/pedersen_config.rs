use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveGroup,
    AffineRepr,
};

use ark_std::{UniformRand, ops::Mul};
use std::ops;
use rand::{RngCore, CryptoRng};

pub trait PedersenConfig : SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;

    /// The curve type that maps to this PedersenConfig.
    /// For example, for T256 it would be P256.
    type OCurve : CurveConfig;

    fn from_oc(x: <Self::OCurve as CurveConfig>::ScalarField) -> <Self as CurveConfig>::ScalarField {
        let x_bt : num_bigint::BigUint = x.into();
        <Self as CurveConfig>::ScalarField::from(x_bt)
    }    
}

#[derive(Clone, Copy)]
pub struct PedersenComm<P: PedersenConfig> {
    pub comm: sw::Affine<P>,
    pub r: <P as CurveConfig>::ScalarField,    
}

impl<P: PedersenConfig> ops::Add<PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output { comm: (self.comm.into_group() + rhs.comm).into(), r: self.r + rhs.r }
    }
}

impl<P: PedersenConfig> ops::Sub<PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output { comm: (self.comm.into_group() - rhs.comm).into(), r: self.r - rhs.r }
    }
}

impl<P: PedersenConfig> PedersenComm<P> {    
    pub fn new<T: RngCore + CryptoRng>(x: <P as CurveConfig>::ScalarField, rng: &mut T) -> Self {
        let x_r = <P as CurveConfig>::ScalarField::rand(rng);
        let x_p = <P as SWCurveConfig>::GENERATOR.mul(x) + P::GENERATOR2.mul(x_r);
        Self {comm: x_p.into_affine(), r: x_r }
    }    
}

