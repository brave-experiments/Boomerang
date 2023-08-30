use crate::{Projective, Config};
use ark_algebra_test_templates::*;
use ark_std::{UniformRand};
use ark_ec::{CurveConfig};
use pedersen::{PedersenComm};

test_group!(g1; Projective; sw);

type PC = PedersenComm<Config>;

#[test]
fn test_pedersen() {
    let mut rng = ark_std::test_rng();
    let a = <Config as CurveConfig>::ScalarField::rand(&mut rng);
    let b = <Config as CurveConfig>::ScalarField::rand(&mut rng); 
    let c : PC = PC::new(a, b, &mut rng);
    assert!(c.x_comm.is_on_curve());
    assert!(c.y_comm.is_on_curve());
}
