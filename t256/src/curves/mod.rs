use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

use pedersen::pedersen_config::PedersenConfig;

use ark_ff::BigInt;
use ark_ff::{Field, MontConfig, MontFp};

use crate::{fq::Fq, fr::Fr, fr::FrConfig};

use ark_secp256r1::Config as secp256r1conf;
use ark_secp256r1::Fq as secp256r1Fq;
use ark_secp256r1::FqConfig as secp256FqConfig;
type OtherBaseField = <secp256r1conf as CurveConfig>::BaseField;

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

impl From<BigInt<4>> for FrStruct {
    fn from(x: BigInt<4>) -> Self {
        let x_t = FrConfig::from_bigint(x).unwrap();
        FrStruct::new(x_t)
    }
}

impl Into<BigInt<4>> for FrStruct {
    fn into(self) -> BigInt<4> {
        FrConfig::into_bigint(self.0)
    }
}

struct Secp256r1base(OtherBaseField);

impl Secp256r1base {
    pub fn new(x: secp256r1Fq) -> Secp256r1base {
        Secp256r1base(x)
    }
}

impl Into<BigInt<4>> for Secp256r1base {
    fn into(self) -> BigInt<4> {
        secp256FqConfig::into_bigint(self.0)
    }
}

impl From<BigInt<4>> for Secp256r1base {
    fn from(x: BigInt<4>) -> Self {
        let x_t = secp256FqConfig::from_bigint(x).unwrap();
        Secp256r1base::new(x_t)
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
    const COEFF_A: Fq =
        MontFp!("115792089210356248762697446949407573530594504085698471288169790229257723883796");

    /// COEFF_B = a6 in the docs, which is a very large string.
    const COEFF_B: Fq =
        MontFp!("81531206846337786915455327229510804132577517753388365729879493166393691077718");

    /// GENERATOR = (G_GENERATOR_X, G_GENERATOR_Y)
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

impl PedersenConfig for Config {
    type OCurve = secp256r1conf;

    /// GENERATOR2 = (G_GENERATOR_X2, G_GENERATOR_Y2)
    const GENERATOR2: Affine = Affine::new_unchecked(G_GENERATOR_X2, G_GENERATOR_Y2);

    fn from_ob_to_sf(x: OtherBaseField) -> <Config as CurveConfig>::ScalarField {
        let x_t: BigInt<4> = x.into();
        let x_v: FrStruct = FrStruct::from(x_t);
        x_v.as_fr()
    }
}

/// G_GENERATOR_X = 3
pub const G_GENERATOR_X: Fq = MontFp!("3");

/// G_GENERATOR_Y = 40902200210088653215032584946694356296222563095503428277299570638400093548589
pub const G_GENERATOR_Y: Fq =
    MontFp!("40902200210088653215032584946694356296222563095503428277299570638400093548589");

/// G_GENERATOR_X2 = 5
pub const G_GENERATOR_X2: Fq = MontFp!("5");

/// G_GENERATOR_Y2 = 28281484859698624956664858566852274012236038028101624500031073655422126514829

pub const G_GENERATOR_Y2: Fq =
    MontFp!("28281484859698624956664858566852274012236038028101624500031073655422126514829");

// We also need to define the ability to convert between points on the NIST curve and points on the Tom Curve,
// which means that we need to be able to take BaseField values from P256 and turn them into ScalarField values
// on T256.
// This is not supported by arkworks, so we'll do it manually.
