//!
//! Module containing the definition of the private key container
//!

use crate::{config::ACLConfig, config::StateSignatureComm};
use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use digest::{ExtendableOutputDirty, Update, XofReader};
