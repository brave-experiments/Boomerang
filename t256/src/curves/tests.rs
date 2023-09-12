use crate::{Config, Projective};
use ark_algebra_test_templates::*;
use ark_ec::short_weierstrass::{self as sw};
use ark_secp256r1::Config as secp256r1conf;
use pedersen_test_templates::test_pedersen;

type OtherProject = sw::Projective<secp256r1conf>;

test_group!(g1; Projective; sw);
test_pedersen!(tp; Config, OtherProject);
