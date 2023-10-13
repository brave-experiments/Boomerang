use crate::{constraints::FqVar, *};
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;

/// A group element in the 384-bit prime order curve.
pub type GVar = ProjectiveVar<Config, FqVar>;

#[test]
fn test() {
    ark_curve_constraint_tests::curves::sw_test::<Config, GVar>().unwrap();
}
