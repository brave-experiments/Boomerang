use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};
use ark_ff::Zero;

use crate::{fq::Fq, fr::Fr, fr::FrConfig};
use ark_secp256k1::Config as secp256k1conf;
use ark_secp256k1::Fq as secp256k1Fq;
use ark_secp256k1::FqConfig as secp256FqConfig;
use ark_secp256k1::Fr as secp256k1Fr;
#[allow(unused_imports)]
use ark_secp256k1::FrConfig as secp256FrConfig;
#[warn(unused_imports)]
use boomerang_macros::derive_conversion;

#[cfg(test)]
mod tests;

pub type Affine = sw::Affine<Config>;
pub type Projective = sw::Projective<Config>;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Config;

impl CurveConfig for Config {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    #[rustfmt::skip]
    const COFACTOR_INV: Fr =  Fr::ONE;
}

impl SWCurveConfig for Config {
    /// COEFF_A = 0
    const COEFF_A: Fq = Fq::ZERO;

    /// COEFF_B = 7
    const COEFF_B: Fq = MontFp!("7");

    /// GENERATOR = (G_GENERATOR_X, G_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

/// G_GENERATOR_X =
/// 55066263022277343669578718895168534326250603453777594175500187360389116729240
pub const G_GENERATOR_X: Fq =
    MontFp!("55066263022277343669578718895168534326250603453777594175500187360389116729240");

/// G_GENERATOR_Y =
/// 32670510020758816978083085130507043184471273380659243275938904335757337482424
pub const G_GENERATOR_Y: Fq =
    MontFp!("32670510020758816978083085130507043184471273380659243275938904335757337482424");

/// G_GENERATOR_X2 = 65485170049033141755572552932091555440395722142984193594072873483228125624049
pub const G_GENERATOR_X2: Fq =
    MontFp!("65485170049033141755572552932091555440395722142984193594072873483228125624049");

/// G_GENERATOR_Y2 = 73163377763031141032501259779738441094247887834941211187427503803434828368457
pub const G_GENERATOR_Y2: Fq =
    MontFp!("73163377763031141032501259779738441094247887834941211187427503803434828368457");

// Now we instantiate everything else.
derive_conversion!(
    Config,
    4,
    128,
    secp256k1conf,
    G_GENERATOR_X2,
    G_GENERATOR_Y2,
    Fr,
    FrConfig,
    secp256k1Fq,
    secp256k1Fr,
    secp256FqConfig,
    secp256FrConfig,
    Affine,
    "65485170049033141755572552932091555440395722142984193594072873483228125624049",
    "73163377763031141032501259779738441094247887834941211187427503803434828368457",
    Config,
    Config
);
