use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
};

pub trait PedersenConfig : SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;
}

