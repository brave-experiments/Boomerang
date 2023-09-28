//! This file just defines a collective of operations
//! for CDLS.

use crate::{
    collective::Collective, ec_point_add_protocol::ECPointAddProof,
    pedersen_config::PedersenConfig, scalar_mul_protocol::ECScalarMulProof,
};

pub struct CDLSCollective;
impl<P: PedersenConfig> Collective<P> for CDLSCollective {
    type PointAdd = ECPointAddProof<P>;
    type ScalarMul = ECScalarMulProof<P>;
}
