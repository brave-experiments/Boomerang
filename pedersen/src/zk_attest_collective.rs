//! This file just defines a collective of operations
//! for ZKAttest.

use crate::{
    collective::Collective, pedersen_config::PedersenConfig,
    zk_attest_point_add_protocol::ZKAttestPointAddProof,
    zk_attest_scalar_mul_protocol::ZKAttestECScalarMulProof,
};

pub struct ZKAttestCollective;
impl<P: PedersenConfig> Collective<P> for ZKAttestCollective {
    type PointAdd = ZKAttestPointAddProof<P>;
    type ScalarMul = ZKAttestECScalarMulProof<P>;
}
