use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

use pedersen::pedersen_config::PedersenConfig;

use ark_ff::BigInt;
use ark_ff::{Field, MontConfig, MontFp};

use crate::{fq::Fq, fr::Fr, fr::FrConfig};

use ark_secp384r1::Config as secp384r1conf;
use ark_secp384r1::Fq as secp384r1Fq;
use ark_secp384r1::FqConfig as secp384FqConfig;
type OtherBaseField = <secp384r1conf as CurveConfig>::BaseField;

// Define the various conversion structs.
struct FrStruct(Fr);
impl FrStruct {
    pub fn new(x: Fr) -> FrStruct {
        FrStruct(x)
    }

    pub fn as_fr(&self) -> Fr {
        self.0
    }
}

impl From<BigInt<6>> for FrStruct {
    fn from(x: BigInt<6>) -> Self {
        let x_t = FrConfig::from_bigint(x).unwrap();
        FrStruct::new(x_t)
    }
}

impl From<FrStruct> for BigInt<6> {
    fn from(val: FrStruct) -> Self {
        FrConfig::into_bigint(val.0)
    }
}

struct Secp384r1base(OtherBaseField);

impl Secp384r1base {
    pub fn new(x: secp384r1Fq) -> Secp384r1base {
        Secp384r1base(x)
    }
}

impl From<Secp384r1base> for BigInt<6> {
    fn from(val: Secp384r1base) -> Self {
        secp384FqConfig::into_bigint(val.0)
    }
}

impl From<BigInt<6>> for Secp384r1base {
    fn from(x: BigInt<6>) -> Self {
        let x_t = secp384FqConfig::from_bigint(x).unwrap();
        Secp384r1base::new(x_t)
    }
}

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

impl PedersenConfig for Config {
    type OCurve = secp384r1conf;

    /// GENERATOR2 = (G_GENERATOR_X2, G_GENERATOR_Y2)
    const GENERATOR2: Affine = Affine::new_unchecked(G_GENERATOR_X2, G_GENERATOR_Y2);

    fn from_ob_to_sf(x: OtherBaseField) -> <Config as CurveConfig>::ScalarField {
        let x_t: BigInt<6> = x.into();
        let x_v: FrStruct = FrStruct::from(x_t);
        x_v.as_fr()
    }
}

/// G_GENERATOR_X = 18624522857557105898096886988538082729570911703609840597859472552101056293848159295245991160598223034723589185598549
pub const G_GENERATOR_X : Fq = MontFp!("18624522857557105898096886988538082729570911703609840597859472552101056293848159295245991160598223034723589185598549");

/// G_GENERATOR_Y = 16812635070577401701780555151784939373443796894181112771346367209071849423738982329774175396215506669421943316852710
pub const G_GENERATOR_Y : Fq = MontFp!("16812635070577401701780555151784939373443796894181112771346367209071849423738982329774175396215506669421943316852710");

/// G_GENERATOR_X2 = 5
pub const G_GENERATOR_X2: Fq = MontFp!("5");

/// G_GENERATOR_Y2 = 6363885786003242131136944941369369468464707802299146445548164183900284786157464900151666199152091187308687891798230
pub const G_GENERATOR_Y2 : Fq = MontFp!("6363885786003242131136944941369369468464707802299146445548164183900284786157464900151666199152091187308687891798230");
