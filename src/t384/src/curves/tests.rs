use crate::{Projective, Config};
use ark_algebra_test_templates::*;
use ark_std::{UniformRand};

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
    AffineRepr,
    CurveGroup,
};

use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig, equality_protocol::EqualityProof as EP, opening_protocol::OpeningProof as OP, mul_protocol::MulProof as MP, ec_point_add_protocol::ECPointAddProof as EPAP};
use rand_core::OsRng;
use merlin::Transcript;
use ark_secp384r1::Config as secp384r1conf;

test_group!(g1; Projective; sw);

type PC = PedersenComm<Config>;
type OtherProjectiveType = sw::Projective<secp384r1conf>;

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
fn test_pedersen_add() {
    // Test that adding two random pedersen commitments works.
    let a = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c1 : PC = PC::new(a, &mut OsRng);
    assert!(c1.comm.is_on_curve());

    let b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c2 : PC = PC::new(b, &mut OsRng);
    assert!(c2.comm.is_on_curve());

    let c3 = c1 + c2;

    let c_act : sw::Affine<Config> = (c1.comm.into_group() + c2.comm).into();
    assert!(c3.comm == c_act);
    assert!(c3.r == c1.r + c2.r);   

    // Same if by reference.
    let c3r = c1 + &c2;
    assert!(c3r.comm == c_act);
    assert!(c3r.r == c1.r + c2.r);

    // Or if by reference the other way.
    let c3rv = &c1 + c2;
    assert!(c3rv.comm == c_act);
    assert!(c3rv.r == c1.r + c2.r);

    // Or even if both.
    let c3rr = &c1 + &c2;
    assert!(c3rr.comm == c_act);
    assert!(c3rr.r == c1.r + c2.r);    
}

#[test]
fn test_pedersen_sub() {
    // Same as for addition, but subtraction instead.
    let a = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c1 : PC = PC::new(a, &mut OsRng);
    assert!(c1.comm.is_on_curve());

    let b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    let c2 : PC = PC::new(b, &mut OsRng);
    assert!(c2.comm.is_on_curve());

    let c3 = c1 - c2;

    let c_act : sw::Affine<Config> = (c1.comm.into_group() - c2.comm).into();
    assert!(c3.comm == c_act);
    assert!(c3.r == c1.r - c2.r);


    // Same if by reference.
    let c3r = c1 - &c2;
    assert!(c3r.comm == c_act);
    assert!(c3r.r == c1.r - c2.r);

    // Or if by reference the other way.
    let c3rv = &c1 - c2;
    assert!(c3rv.comm == c_act);
    assert!(c3rv.r == c1.r - c2.r);

    // Or even if both.
    let c3rr = &c1 - &c2;
    assert!(c3rr.comm == c_act);
    assert!(c3rr.r == c1.r - c2.r);    
    
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
    assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm));

    // Alternatively, check that a different proof would fail.
    let mut b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if b != a { break; }
        b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }
    
    let c3 : PC = PC::new(b, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1.comm, &c3.comm));
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
    assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm));

    // Alternatively, check that a different proof would fail.
    let mut b = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);
    
    loop {
        if b != a { break; }
        b = <<Config as PedersenConfig>::OCurve as CurveConfig>::ScalarField::rand(&mut OsRng);        
    }
    
    let c3 : PC = PC::new(<Config as PedersenConfig>::from_oc(b), &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1.comm, &c3.comm));
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
    assert!(proof.verify(&mut transcript_v, &c1.comm));

    // Now check that an unrelated commitment would fail.
    // Alternatively, check that a different proof would fail.
    let mut b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if b != a { break; }
        b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }
    
    let c3 : PC = PC::new(b, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c3.comm));
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
    assert!(proof.verify(&mut transcript_v, &c1.comm));

    // Now check that an unrelated commitment would fail.
    // Alternatively, check that a different proof would fail.
    let mut b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if b != a { break; }
        b = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }
    
    let c3 : PC = PC::new(b, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c3.comm));
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
    let proof = MP::create(&mut transcript, &mut OsRng, &a, &b, &c1, &c2, &c3);    
    assert!(proof.alpha.is_on_curve());
    assert!(proof.beta.is_on_curve());
    assert!(proof.delta.is_on_curve());

    // Now check that the proof verifies.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm, &c3.comm));

    // And now check it would fail on a different c3 value.

    let mut d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if d != z {break;}
        d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }

    let c4 : PC = PC::new(d, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1.comm, &c2.comm, &c4.comm));    
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
    let proof = MP::create(&mut transcript, &mut OsRng, &a, &b, &c1, &c2, &c3);    
    assert!(proof.alpha.is_on_curve());
    assert!(proof.beta.is_on_curve());
    assert!(proof.delta.is_on_curve());

    // Now check that the proof verifies.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm, &c3.comm));

    // And now check it would fail on a different c3 value.

    let mut d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);

    loop {
        if d != z {break;}
        d = <Config as CurveConfig>::ScalarField::rand(&mut OsRng);
    }

    let c4 : PC = PC::new(d, &mut OsRng);
    let mut transcript_f = Transcript::new(label);
    assert!(!proof.verify(&mut transcript_f, &c1.comm, &c2.comm, &c4.comm));    
}


#[test]
fn test_pedersen_point_add() {
    // Test that the point addition proof goes through.
    let label = b"PedersenECPointAdd";
    let a     = OtherProjectiveType::rand(&mut OsRng).into_affine();
    let mut b     = OtherProjectiveType::rand(&mut OsRng).into_affine();

    loop {
        if b != a { break; }
        b = OtherProjectiveType::rand(&mut OsRng).into_affine();
    }
    
    // Note: this needs to be forced into affine too, or the underlying
    // proof system breaks (this seems to be an ark_ff thing).
    let t = (a + b).into_affine();

    let mut transcript = Transcript::new(label);
    let proof : EPAP<Config> = EPAP::create(&mut transcript, &mut OsRng, a.x, a.y, b.x, b.y, t.x, t.y);

    assert!(proof.c1.is_on_curve());
    assert!(proof.c2.is_on_curve());
    assert!(proof.c3.is_on_curve());
    assert!(proof.c4.is_on_curve());
    assert!(proof.c5.is_on_curve());
    assert!(proof.c6.is_on_curve());
    assert!(proof.c7.is_on_curve());

    // Now check that it verifies.
    let mut transcript_v = Transcript::new(label);
    assert!(proof.verify(&mut transcript_v));

    // Alternatively, generate a false proof and watch it fail.
    let mut tf = OtherProjectiveType::rand(&mut OsRng).into_affine();
    loop {
        if tf != t { break; }
        tf = OtherProjectiveType::rand(&mut OsRng).into_affine();
    }

    // Now show it fails.
    let mut transcript_f1 = Transcript::new(label);
    let proof_f : EPAP<Config> = EPAP::create(&mut transcript_f1, &mut OsRng, a.x, a.y, b.x, b.y, tf.x, tf.y);

    let mut transcript_f2 = Transcript::new(label);
    assert!(!proof_f.verify(&mut transcript_f2));
}

