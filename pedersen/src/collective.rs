//! This file implements a trait "Collective" that allows one to group together useful
//! and related protocols into a single trait. This is primarily to make meta-programming
//! easier.
//! For example, you might use this to group the ZKAttest protocols together.

use crate::{
    pedersen_config::PedersenConfig, point_add::PointAddProtocol, scalar_mul::ScalarMulProtocol,
};

pub trait Collective<P: PedersenConfig> {
    /// PointAdd. This protocol abstracts away a point addition proof over `P`.
    type PointAdd: PointAddProtocol<P>;

    /// ScalarMul. This protocol abstracts away a scalar multiplication proof.
    type ScalarMul: ScalarMulProtocol<P>;
}
