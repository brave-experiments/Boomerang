use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

use crate::{fq::Fq, fr::Fr, fr::FrConfig};
use cdls_macros::derive_conversion;
use ark_secp256k1::Config as secp256k1conf;
use ark_secp256k1::Fq as secp256k1Fq;
use ark_secp256k1::FqConfig as secpk256FqConfig;

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
    const COEFF_A : Fq = MontFp!("109944947385183287114744912266911522476262726606489319303438596785742669821412");
        
    /// COEFF_B = a6 in the docs, which is a very large string.
    const COEFF_B : Fq = MontFp!("103809634340668564235099596520993680094951757055289709302696051708320017156366");
    
    /// GENERATOR = (G_GENERATOR_X, G_GENERATOR_Y)
    const GENERATOR : Affine = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);    
}

/// G_GENERATOR_X = 115792089237316195423570985008687907853634386693684621307141857813043191627550
pub const G_GENERATOR_X : Fq = MontFp!("115792089237316195423570985008687907853634386693684621307141857813043191627550");

/// G_GENERATOR_Y = 49623685273574878364288912178919778381322153136347948717277895919435228877620
pub const G_GENERATOR_Y : Fq = MontFp!("40902200210088653215032584946694356296222563095503428277299570638400093548589");

/// G_GENERATOR_X2 = 51563758570785615094394677840154565417233073457987476322548881811253643782808
pub const G_GENERATOR_X2 : Fq = MontFp!("51563758570785615094394677840154565417233073457987476322548881811253643782808");

/// G_GENERATOR_Y2 = 62304204463291146846401348483946960582197037517224766771016538601960428597955
pub const G_GENERATOR_Y2 : Fq = MontFp!("28281484859698624956664858566852274012236038028101624500031073655422126514829");

// Now we instantiate everything else.
derive_conversion!(Config, 4, secp256k1conf, G_GENERATOR_X2, G_GENERATOR_Y2, Fr, FrConfig, secp256k1Fq, secpk256FqConfig, Affine);
