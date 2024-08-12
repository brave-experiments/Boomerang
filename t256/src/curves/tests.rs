use crate::{Config, Projective};
use ark_algebra_test_templates::*;
use ark_ec::short_weierstrass::{self as sw};
use ark_secp256r1::Config as secp256r1conf;
use boomerang_macros::{test_acl, test_boomerang, test_pedersen};

type OtherProject = sw::Projective<secp256r1conf>;

test_group!(g1; Projective; sw);
test_pedersen!(tp; Config, OtherProject);
test_acl!(acl; Config, Config, OtherProject);
test_boomerang!(boomerang; Config, Config, Config, OtherProject);
