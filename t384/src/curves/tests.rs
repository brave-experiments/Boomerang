use crate::{Config, Projective};
use ark_algebra_test_templates::*;
use ark_ec::short_weierstrass::{self as sw};
use ark_secp384r1::Config as secp384r1conf;
use boomerang_macros::test_acl;
use boomerang_macros::test_boomerang;
use boomerang_macros::test_pedersen;

type OtherProject = sw::Projective<secp384r1conf>;

test_group!(g1; Projective; sw);
test_pedersen!(tp; Config, OtherProject);
test_acl!(acl; Config, Config, OtherProject);
test_boomerang!(boomerang; Config, Config, Config, OtherProject);
