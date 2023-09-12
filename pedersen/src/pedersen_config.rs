use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use ark_serialize::CanonicalDeserialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};
use std::ops;

pub trait PedersenConfig: SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;

    /// The curve type that maps to this PedersenConfig.
    /// For example, for T256 it would be P256.
    type OCurve: CurveConfig + SWCurveConfig;

    fn from_oc(
        x: <Self::OCurve as CurveConfig>::ScalarField,
    ) -> <Self as CurveConfig>::ScalarField {
        let x_bt: num_bigint::BigUint = x.into();
        <Self as CurveConfig>::ScalarField::from(x_bt)
    }

    fn from_ob_to_sf(
        x: <Self::OCurve as CurveConfig>::BaseField,
    ) -> <Self as CurveConfig>::ScalarField;

    /// This function turns a challenge buffer into a challenge point. This is primarily to circumvent
    /// an issue with Merlin (which primarily deals with Ristretto points).
    fn make_challenge_from_buffer(chal_buf: &[u8]) -> <Self as CurveConfig>::ScalarField {
        <Self as CurveConfig>::ScalarField::deserialize_compressed(chal_buf).unwrap()
    }
}

#[derive(Copy, Clone)]
pub struct PedersenComm<P: PedersenConfig> {
    pub comm: sw::Affine<P>,
    pub r: <P as CurveConfig>::ScalarField,
}

impl<P: PedersenConfig> ops::Add<PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Add<&PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Add<&PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Add<PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<&PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<&PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> PedersenComm<P> {
    pub fn new<T: RngCore + CryptoRng>(x: <P as CurveConfig>::ScalarField, rng: &mut T) -> Self {
        Self::new_with_generators(x, rng, &<P as SWCurveConfig>::GENERATOR, &P::GENERATOR2)
    }

    pub fn new_with_generators<T: RngCore + CryptoRng>(
        x: <P as CurveConfig>::ScalarField,
        rng: &mut T,
        g: &sw::Affine<P>,
        q: &sw::Affine<P>,
    ) -> Self {
        // Returns a new pedersen commitment using fixed generators.
        let x_r = <P as CurveConfig>::ScalarField::rand(rng);
        let x_p = g.mul(x) + q.mul(x_r);
        Self {
            comm: x_p.into_affine(),
            r: x_r,
        }
    }
}
