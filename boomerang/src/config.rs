use ark_ec::{models::CurveConfig, short_weierstrass::SWCurveConfig};

use crate::client::{Token, UKeyPair};
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
    /// The token state
    pub token_state: Vec<Token<B>>,
    /// The user keypair
    pub c_key_pair: UKeyPair<B>,
}
