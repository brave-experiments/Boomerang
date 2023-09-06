use crate::{Projective, Config};
use ark_algebra_test_templates::*;
use ark_std::{UniformRand};
use ark_ec::{CurveConfig};

use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig, equality_protocol::EqualityProof as EP, opening_protocol::OpeningProof as OP, mul_protocol::MulProof as MP};
use rand_core::OsRng;
use merlin::Transcript;

test_group!(g1; Projective; sw);

type PC = PedersenComm<Config>;

#[test]
fn test_pedersen() {
    // Test that committing to a random point works.
    let a = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c : PC = PC::new(a, &mut OsRng);
    assert!(c.comm.is_on_curve());
}

#[test]
fn test_pedersen_convert() {
    // Test that a commitment from the NIST curve to the T curve works.
    let a = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c : PC = PC::new(<Config as PedersenConfig>::from_oc(a), &mut OsRng);
    assert!(c.comm.is_on_curve());
}

#[test]
fn test_pedersen_equality() {
    // Test that the equality proof goes through.
    let label = b"PedersenEq";
    
    let a = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c1 : PC = PC::new(a, &mut OsRng);
    let c2 : PC = PC::new(a, &mut OsRng);

    let mut transcript = Transcript::new(label);

    // Build the proof.
    let proof = EP::create(&mut transcript, &mut OsRng, &c1, &c2);
    assert!(proof.alpha.is_on_curve());

    // Make a new transcript and use that to verify.
    let mut transcript_v = Transcript::new(label);
    
    // Now check that the proof verifies properly.
    assert!(proof.verify(&mut transcript_v, &c1, &c2));

    // Alternatively, check that a different proof would fail.
    let mut b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if b != a { break; }
        b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }
    
    let c3 : PC = PC::new(b, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1, &c3));
}

#[test]
fn test_pedersen_equality_nist() {
    // Test that the equality proof goes through.
    let label = b"PedersenEq";

    let a = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c1 : PC = PC::new(<Config as PedersenConfig>::from_oc(a), &mut OsRng);
    let c2 : PC = PC::new(<Config as PedersenConfig>::from_oc(a), &mut OsRng);

    let mut transcript = Transcript::new(label);

    // Build the proof.
    let proof = EP::create(&mut transcript, &mut OsRng, &c1, &c2);
    assert!(proof.alpha.is_on_curve());

    // Make a new transcript and use that to verify.
    let mut transcript_v = Transcript::new(label);
    
    // Now check that the proof verifies properly.
    assert!(proof.verify(&mut transcript_v, &c1, &c2));

    // Alternatively, check that a different proof would fail.
    let mut b = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);
    
    loop {
        if b != a { break; }
        b = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);        
    }
    
    let c3 : PC = PC::new(<Config as PedersenConfig>::from_oc(b), &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1, &c3));
}

#[test]
fn test_pedersen_opening() {
    // Test that the opening proof goes through.
    let label = b"PedersenOpen";
    
    let a = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c1 : PC = PC::new(a, &mut OsRng);
    let mut transcript = Transcript::new(label);

    let proof = OP::create(&mut transcript, &mut OsRng, &a, &c1);
    assert!(proof.alpha.is_on_curve());

    // Now check that the proof verifies correctly.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v, &c1));

    // Now check that an unrelated commitment would fail.
    // Alternatively, check that a different proof would fail.
    let mut b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if b != a { break; }
        b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }
    
    let c3 : PC = PC::new(b, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c3));
}

#[test]
fn test_pedersen_opening_nist() {
    // Test that the opening proof goes through.
    let label = b"PedersenOpen";

    let a_t = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);
    let a   = <Config as PedersenConfig>::from_oc(a_t);

    let c1 : PC = PC::new(a, &mut OsRng);
        
    let mut transcript = Transcript::new(label);

    let proof = OP::create(&mut transcript, &mut OsRng, &a, &c1);
    assert!(proof.alpha.is_on_curve());

    // Now check that the proof verifies correctly.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v, &c1));

    // Now check that an unrelated commitment would fail.
    // Alternatively, check that a different proof would fail.
    let mut b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if b != a { break; }
        b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }
    
    let c3 : PC = PC::new(b, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c3));
}

#[test]
fn test_pedersen_mul() {
    // Test that the mul proof goes through.
    let label = b"PedersenMul";

    let a = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let z = a * b;
    
    let c1 : PC = PC::new(a, &mut OsRng);
    let c2 : PC = PC::new(b, &mut OsRng);
    let c3 : PC = PC::new(z, &mut OsRng);

    let mut transcript = Transcript::new(label);
    let proof = MP::create(&mut transcript, &mut OsRng, a, b, &c1, &c2, &c3);    
    assert!(proof.alpha.is_on_curve());
    assert!(proof.beta.is_on_curve());
    assert!(proof.delta.is_on_curve());

    // Now check that the proof verifies.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v, &c1, &c2, &c3));

    // And now check it would fail on a different c3 value.

    let mut d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if d != z {break;}
        d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }

    let c4 : PC = PC::new(d, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1, &c2, &c4));    
}

#[test]
fn test_pedersen_mul_nist() {
    // Test that the mul proof goes through.
    let label = b"PedersenMul";

    let a_t = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);
    let b_t = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);

    let a = <Config as PedersenConfig>::from_oc(a_t);
    let b = <Config as PedersenConfig>::from_oc(b_t);

    let z = a * b;
    
    let c1 : PC = PC::new(a, &mut OsRng);
    let c2 : PC = PC::new(b, &mut OsRng);
    let c3 : PC = PC::new(z, &mut OsRng);

    let mut transcript = Transcript::new(label);
    let proof = MP::create(&mut transcript, &mut OsRng, a, b, &c1, &c2, &c3);    
    assert!(proof.alpha.is_on_curve());
    assert!(proof.beta.is_on_curve());
    assert!(proof.delta.is_on_curve());

    // Now check that the proof verifies.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v, &c1, &c2, &c3));

    // And now check it would fail on a different c3 value.

    let mut d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if d != z {break;}
        d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }

    let c4 : PC = PC::new(d, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1, &c2, &c4));    
}
