use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use ark_std::{ops::Mul, UniformRand};
use digest::{ExtendableOutputDirty, Update, XofReader};
use rand::{CryptoRng, RngCore};
use sha3::Shake256;

use acl::{config::ACLConfig, sign::SigSign};
use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig};

pub trait BoomerangConfig: SWCurveConfig {
    /// The curve type that maps to this Config.
    /// For example, for T256 it would be P256.
    /// This curve type needs to be both a CurveConfig (so we can access the ScalarField / BaseField
    /// structures) and a SWCurveConfig (so we can access the generators).
    type OCurve: CurveConfig + SWCurveConfig;

    type Pedersen: PedersenConfig;
    type ACL: ACLConfig;
}

/// Boomerang token
#[derive(Clone)]
#[must_use]
pub struct Token<B: BoomerangConfig> {
    /// Serial Number
    id: <B as CurveConfig>::ScalarField,
    /// The value
    v: <B as CurveConfig>::ScalarField,
    /// User's secret key
    sk: <B as CurveConfig>::ScalarField,
    /// Random value
    r: <B as CurveConfig>::ScalarField,
}

/// Boomerang state.
///
#[derive(Clone)]
#[must_use]
pub struct State<B: BoomerangConfig> {
    /// The token state
    pub state: Vec<Token<B>>,
    /// The signature state
    pub sig_state: SigSign<B::ACL>,
}

impl<B: BoomerangConfig> State<B> {
    /// Boomerang state
    pub const fn state(&self) -> &Vec<Token<B>> {
        &self.state
    }
}
