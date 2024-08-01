use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

#[warn(unused_imports)]
use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_ff::{BigInt, Field, MontFp};
use ark_secp256r1::Config as secp256r1conf;
use ark_secp256r1::Fq as secp256r1Fq;
use ark_secp256r1::FqConfig as secp256FqConfig;
use ark_secp256r1::Fr as secp256r1Fr;
#[allow(unused_imports)]
// This is actually used in the macro below, but rustfmt seems to
// be unable to deduce that...
use ark_secp256r1::FrConfig as secp256FrConfig;

#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530594504085698471288169790229257723883799"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951"]
#[generator = "1"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

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
    const COFACTOR_INV: Fr = Fr::ONE;
}

/// G_GENERATOR_X = 3
pub const G_GENERATOR_X: Fq = MontFp!("3");

/// G_GENERATOR_Y = 40902200210088653215032584946694356296222563095503428277299570638400093548589
pub const G_GENERATOR_Y: Fq =
    MontFp!("40902200210088653215032584946694356296222563095503428277299570638400093548589");

impl SWCurveConfig for Config {
    const COEFF_A: Fq =
        MontFp!("115792089210356248762697446949407573530594504085698471288169790229257723883796");
    const COEFF_B: Fq =
        MontFp!("81531206846337786915455327229510804132577517753388365729879493166393691077718");
    const GENERATOR: Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);
}

/// G_GENERATOR_X2 = 5
pub const G_GENERATOR_X2: Fq = MontFp!("5");

/// G_GENERATOR_Y2 = 28281484859698624956664858566852274012236038028101624500031073655422126514829
pub const G_GENERATOR_Y2: Fq =
    MontFp!("28281484859698624956664858566852274012236038028101624500031073655422126514829");

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
        let x_t = <FrConfig>::from_bigint(x).unwrap();
        FrStruct::new(x_t)
    }
}

impl From<FrStruct> for BigInt<4> {
    fn from(val: FrStruct) -> Self {
        FrConfig::into_bigint(val.0)
    }
}

type OtherBaseField = <secp256r1conf as CurveConfig>::BaseField;
type OtherScalarField = <secp256r1conf as CurveConfig>::ScalarField;

struct OtherScalar(OtherScalarField);
impl OtherScalar {
    pub fn new(x: secp256r1Fr) -> OtherScalar {
        OtherScalar(x)
    }

    pub fn as_fr(&self) -> OtherScalarField {
        self.0
    }
}

impl From<OtherScalar> for BigInt<4> {
    fn from(x: OtherScalar) -> Self {
        <secp256FrConfig>::into_bigint(x.0)
    }
}

impl From<BigInt<4>> for OtherScalar {
    fn from(x: BigInt<4>) -> OtherScalar {
        let x_t = <secp256FrConfig>::from_bigint(x).unwrap();
        OtherScalar::new(x_t)
    }
}

// via a macro
macro_rules! StrToFr {
    ($c0:expr) => {{
        let (is_positive, limbs) = ark_ff_macros::to_sign_and_limbs!($c0);
        <Fr>::from_sign_and_limbs(is_positive, &limbs)
    }};
}

macro_rules! StrToOtherFq {
    ($c0:expr) => {{
        let (is_positive, limbs) = ark_ff_macros::to_sign_and_limbs!($c0);
        <secp256r1Fq>::from_sign_and_limbs(is_positive, &limbs)
    }};
}

use pedersen::pedersen_config::PedersenConfig;
// The actual pedersen config
impl PedersenConfig for Config {
    type OCurve = secp256r1conf;

    const SECPARAM: usize = 128;

    /// GENERATOR2 = (G2_X, G2_Y)
    const GENERATOR2: Affine = <Affine>::new_unchecked(G_GENERATOR_X2, G_GENERATOR_Y2);

    fn from_ob_to_sf(x: OtherBaseField) -> <Config as CurveConfig>::ScalarField {
        let x_t: BigInt<4> = x.into();
        let x_v: FrStruct = FrStruct::from(x_t);
        x_v.as_fr()
    }

    fn from_ob_to_os(x: OtherBaseField) -> <Self::OCurve as CurveConfig>::ScalarField {
        let x_t: BigInt<4> = x.into();
        OtherScalar::from(x_t).as_fr()
    }

    fn from_os_to_sf(x: OtherScalarField) -> <Config as CurveConfig>::ScalarField {
        let x_t: BigInt<4> = x.into();
        let x_v: FrStruct = FrStruct::from(x_t);
        x_v.as_fr()
    }

    fn from_bf_to_sf(x: <Self as CurveConfig>::BaseField) -> <Self as CurveConfig>::ScalarField {
        let x_t: BigInt<4> = x.into();
        let x_v: FrStruct = FrStruct::from(x_t);
        x_v.as_fr()
    }

    fn make_single_bit_challenge(v: u8) -> <Config as CurveConfig>::ScalarField {
        match v {
            0 => Self::CM1,
            1 => Self::CP1,
            _ => panic!("Invalid bit in make_single_bit_challenge {}", v),
        }
    }

    fn from_u64_to_sf(x: u64) -> <Self as CurveConfig>::ScalarField {
        let x_t = BigInt::<4>::from(x);
        let x_v = FrStruct::from(x_t);
        x_v.as_fr()
    }

    const OGENERATOR2: sw::Affine<Self::OCurve> = sw::Affine::<Self::OCurve>::new_unchecked(
        StrToOtherFq!("5"),
        StrToOtherFq!(
            "31468013646237722594854082025316614106172411895747863909393730389177298123724"
        ),
    );

    const CM1: Self::ScalarField = StrToFr!("-1");
    const CP1: Self::ScalarField = StrToFr!("1");
}

use ark_ff::UniformRand;
use pedersen::pedersen_config::PedersenComm;
use rand::rngs::OsRng;

fn main() {
    println!("Hello, world!");

    type PC = PedersenComm<Config>;
    type SF = <Config as CurveConfig>::ScalarField;

    let a = SF::rand(&mut OsRng);
    let c: PC = PC::new(a, &mut OsRng);
}
