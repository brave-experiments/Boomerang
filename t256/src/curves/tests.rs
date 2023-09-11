use crate::{Projective, Config};
use ark_algebra_test_templates::*;
use ark_secp256r1::Config as secp256r1conf;
use cdls_macros::test_pedersen;
use ark_ec::short_weierstrass::{self as sw};

type OtherProject = sw::Projective<secp256r1conf>;

test_group!(g1; Projective; sw);
test_pedersen!(tp; Config, OtherProject);

