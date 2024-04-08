use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

use crate::{fq::Fq, fr::Fr, fr::FrConfig};
use ark_secp384r1::Config as secp384r1conf;
use ark_secp384r1::Fq as secp384r1Fq;
use ark_secp384r1::FqConfig as secp384FqConfig;
use ark_secp384r1::Fr as secp384r1Fr;
#[allow(unused_imports)]
// This is actually used in the macro below, but rustfmt seems to
// be unable to deduce that...
use ark_secp384r1::FrConfig as secp384FrConfig;
#[warn(unused_imports)]
use cdls_macros::derive_conversion;

#[cfg(test)]
mod tests;

pub type Affine = sw::Affine<Config>;
pub type Projective = sw::Projective<Config>;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Config;

impl CurveConfig for Config {
    type BaseField = Fq;
    type ScalarField = Fr;

    // We're dealing with prime order curves.

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    const COFACTOR_INV: Fr = Fr::ONE;
}

impl SWCurveConfig for Config {
    /// COEFF_A = a4 in the docs, which is a very large string.
    const COEFF_A : Fq = MontFp!("20026862879313379863654166607105301622642181700373777070134388010349273891892149760539610171757683236290527048057018");

    /// COEFF_B = a6 in the docs, which is a very large string.
    const COEFF_B : Fq = MontFp!("23911602450661234612404882548336064535929415695327240026670179346429452149970125567156571346957298429887433518292555");

    /// GENERATOR = (G_GENERATOR_X, G_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

/// G_GENERATOR_X = 18624522857557105898096886988538082729570911703609840597859472552101056293848159295245991160598223034723589185598549
pub const G_GENERATOR_X : Fq = MontFp!("18624522857557105898096886988538082729570911703609840597859472552101056293848159295245991160598223034723589185598549");

/// G_GENERATOR_Y = 16812635070577401701780555151784939373443796894181112771346367209071849423738982329774175396215506669421943316852710
pub const G_GENERATOR_Y : Fq = MontFp!("16812635070577401701780555151784939373443796894181112771346367209071849423738982329774175396215506669421943316852710");

/// G_GENERATOR_X2 = 5
pub const G_GENERATOR_X2: Fq = MontFp!("5");

/// G_GENERATOR_Y2 = 6363885786003242131136944941369369468464707802299146445548164183900284786157464900151666199152091187308687891798230
pub const G_GENERATOR_Y2 : Fq = MontFp!("6363885786003242131136944941369369468464707802299146445548164183900284786157464900151666199152091187308687891798230");

// Now we instantiate everything else.
derive_conversion!(
    Config,
    6,
    192,
    secp384r1conf,
    G_GENERATOR_X2,
    G_GENERATOR_Y2,
    Fr,
    FrConfig,
    secp384r1Fq,
    secp384r1Fr,
    secp384FqConfig,
    secp384FrConfig,
    Affine,
    "35844451280757088535875123965116225310073208726034463360736462178210365192733738092353369333892565847293721646292008",
    "12852303813876583228171852252822018299502069287699403243661957712124279761251434632610206218878102281645617942246021",
    Config
);
