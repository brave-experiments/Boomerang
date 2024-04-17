use ark_ec::{models::CurveConfig, short_weierstrass::SWCurveConfig};

use acl::{config::ACLConfig, sign::SigSign};
use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig};

pub trait BoomerangConfig:
    ACLConfig<OCurve = Self::Curve> + PedersenConfig<OCurve = Self::Curve>
{
    type Curve: CurveConfig + SWCurveConfig;
}

/// Boomerang state.
///
#[derive(Clone)]
pub struct State<B: BoomerangConfig> {
    /// The signature state
    pub sig_state: Vec<SigSign<B>>,
    /// The commitment state
    pub comm_state: Vec<PedersenComm<B>>,
}

impl<B: BoomerangConfig> State<B> {
    /// Boomerang state
    pub const fn state(&self) -> &Vec<PedersenComm<B>> {
        &self.comm_state
    }
}
