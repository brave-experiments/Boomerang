use ark_ec::{models::CurveConfig, short_weierstrass::SWCurveConfig};

use acl::{config::ACLConfig, sign::SigSign};
use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig};

pub trait BoomerangConfig:
    ACLConfig<OCurve = Self::Curve> + PedersenConfig<OCurve = Self::Curve>
{
    type Curve: CurveConfig + SWCurveConfig;
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
    pub sig_state: Vec<SigSign<B>>,
    /// The commitment state
    pub comm_state: Vec<PedersenComm<B>>,
}

impl<B: BoomerangConfig> State<B> {
    /// Boomerang state
    pub const fn state(&self) -> &Vec<Token<B>> {
        &self.state
    }
}
