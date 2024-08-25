use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};
use ark_ff::Zero;

use crate::{fq::Fq, fr::Fr, fr::FrConfig};
use ark_secq256k1::Config as secq256k1conf;
use ark_secq256k1::Fq as secq256k1Fq;
use ark_secq256k1::FqConfig as secq256FqConfig;
use ark_secq256k1::Fr as secq256k1Fr;
#[allow(unused_imports)]
use ark_secq256k1::FrConfig as secq256FrConfig;
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
/// 53718550993811904772965658690407829053653678808745171666022356150019200052646
pub const G_GENERATOR_X: Fq =
    MontFp!("53718550993811904772965658690407829053653678808745171666022356150019200052646");

/// G_GENERATOR_Y =
/// 28941648020349172432234515805717979317553499307621291159490218670604692907903
pub const G_GENERATOR_Y: Fq =
    MontFp!("28941648020349172432234515805717979317553499307621291159490218670604692907903");

/// G_GENERATOR_X2 = 66074285972301200297129825078317149928956243591312218514112646334267511651104
pub const G_GENERATOR_X2: Fq =
    MontFp!("66074285972301200297129825078317149928956243591312218514112646334267511651104");

/// G_GENERATOR_Y2 = 18451814157324471123246799073117578780512506837968746855038596379919570627435
pub const G_GENERATOR_Y2: Fq =
    MontFp!("18451814157324471123246799073117578780512506837968746855038596379919570627435");

// Now we instantiate everything else.
derive_conversion!(
    Config,
    4,
    128,
    secq256k1conf,
    G_GENERATOR_X2,
    G_GENERATOR_Y2,
    Fr,
    FrConfig,
    secq256k1Fq,
    secq256k1Fr,
    secq256FqConfig,
    secq256FrConfig,
    Affine,
    "66074285972301200297129825078317149928956243591312218514112646334267511651104",
    "18451814157324471123246799073117578780512506837968746855038596379919570627435",
    Config,
    Config
);
