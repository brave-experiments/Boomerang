use crate::{Config, Projective};
use ark_algebra_test_templates::*;
use ark_ec::short_weierstrass::{self as sw};
use ark_secq256k1::Config as secq256k1conf;
use boomerang_macros::test_acl;
use boomerang_macros::test_boomerang;
//use boomerang_macros::test_pedersen;

type OtherProject = sw::Projective<secq256k1conf>;

test_group!(g1; Projective; sw);
//test_pedersen!(tp; Config, OtherProject); // we ignore this test here due to this not being a tom curve
test_acl!(acl; Config, Config, OtherProject);
test_boomerang!(boomerang; Config, Config, Config, OtherProject);
