#[macro_export]
#[doc(hidden)]

macro_rules! __test_pedersen {
    ($config: ty, $OtherProjectiveType: ty) => {
        type PC = PedersenComm<$config>;
        type SF = <$config as CurveConfig>::ScalarField;
        type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;

        const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
            <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

        #[test]
        fn test_pedersen() {
            // Test that committing to a random point works.
            let a = SF::rand(&mut OsRng);
            let c: PC = PC::new(a, &mut OsRng);
            assert!(c.comm.is_on_curve());
        }

        #[test]
        fn test_pedersen_convert() {
            // Test that a commitment from the NIST curve to the T curve works.
            let a = OSF::rand(&mut OsRng);
            let c: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);
            assert!(c.comm.is_on_curve());
        }

        #[test]
        fn test_pedersen_add() {
            // Test that adding two random pedersen commitments works.
            let a = SF::rand(&mut OsRng);
            let c1: PC = PC::new(a, &mut OsRng);
            assert!(c1.comm.is_on_curve());

            let b = SF::rand(&mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            assert!(c2.comm.is_on_curve());

            let c3 = c1 + c2;

            let c_act: sw::Affine<Config> = (c1.comm.into_group() + c2.comm).into();
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
            let a = SF::rand(&mut OsRng);
            let c1: PC = PC::new(a, &mut OsRng);
            assert!(c1.comm.is_on_curve());

            let b = SF::rand(&mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            assert!(c2.comm.is_on_curve());

            let c3 = c1 - c2;

            let c_act: sw::Affine<Config> = (c1.comm.into_group() - c2.comm).into();
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

            let a = SF::rand(&mut OsRng);
            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(a, &mut OsRng);

            let mut transcript = Transcript::new(label);

            // Build the proof.
            let proof = EP::create(&mut transcript, &mut OsRng, &c1, &c2);
            assert!(proof.alpha.is_on_curve());

            // Make a new transcript and use that to verify.
            let mut transcript_v = Transcript::new(label);

            // Now check that the proof verifies properly.
            assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm));

            // Alternatively, check that a different proof would fail.
            let mut b = SF::rand(&mut OsRng);

            loop {
                if b != a {
                    break;
                }
                b = SF::rand(&mut OsRng);
            }

            let c3: PC = PC::new(b, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c1.comm, &c3.comm));
        }

        #[test]
        fn test_pedersen_equality_nist() {
            // Test that the equality proof goes through.
            let label = b"PedersenEq";

            let a = OSF::rand(&mut OsRng);
            let c1: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);
            let c2: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);

            let mut transcript = Transcript::new(label);

            // Build the proof.
            let proof = EP::create(&mut transcript, &mut OsRng, &c1, &c2);
            assert!(proof.alpha.is_on_curve());

            // Make a new transcript and use that to verify.
            let mut transcript_v = Transcript::new(label);

            // Now check that the proof verifies properly.
            assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm));

            // Alternatively, check that a different proof would fail.
            let mut b = OSF::rand(&mut OsRng);

            loop {
                if b != a {
                    break;
                }
                b = OSF::rand(&mut OsRng);
            }

            let c3: PC = PC::new(<$config as PedersenConfig>::from_oc(b), &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c1.comm, &c3.comm));
        }

        #[test]
        fn test_pedersen_opening() {
            // Test that the opening proof goes through.
            let label = b"PedersenOpen";

            let a = SF::rand(&mut OsRng);
            let c1: PC = PC::new(a, &mut OsRng);
            let mut transcript = Transcript::new(label);

            let proof = OP::create(&mut transcript, &mut OsRng, &a, &c1);
            assert!(proof.alpha.is_on_curve());

            // Now check that the proof verifies correctly.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm));

            // Now check that an unrelated commitment would fail.
            // Alternatively, check that a different proof would fail.
            let mut b = SF::rand(&mut OsRng);

            loop {
                if b != a {
                    break;
                }
                b = SF::rand(&mut OsRng);
            }

            let c3: PC = PC::new(b, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c3.comm));
        }

        #[test]
        fn test_pedersen_opening_nist() {
            // Test that the opening proof goes through.
            let label = b"PedersenOpen";

            let a_t = OSF::rand(&mut OsRng);
            let a = <$config as PedersenConfig>::from_oc(a_t);

            let c1: PC = PC::new(a, &mut OsRng);

            let mut transcript = Transcript::new(label);

            let proof = OP::create(&mut transcript, &mut OsRng, &a, &c1);
            assert!(proof.alpha.is_on_curve());

            // Now check that the proof verifies correctly.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm));

            // Now check that an unrelated commitment would fail.
            // Alternatively, check that a different proof would fail.
            let mut b = SF::rand(&mut OsRng);

            loop {
                if b != a {
                    break;
                }
                b = SF::rand(&mut OsRng);
            }

            let c3: PC = PC::new(b, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c3.comm));
        }

        #[test]
        fn test_pedersen_mul() {
            // Test that the mul proof goes through.
            let label = b"PedersenMul";

            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let z = a * b;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = MP::create(&mut transcript, &mut OsRng, &a, &b, &c1, &c2, &c3);
            assert!(proof.alpha.is_on_curve());
            assert!(proof.beta.is_on_curve());
            assert!(proof.delta.is_on_curve());

            // Now check that the proof verifies.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm, &c3.comm));

            // And now check it would fail on a different c3 value.

            let mut d = SF::rand(&mut OsRng);

            loop {
                if d != z {
                    break;
                }
                d = SF::rand(&mut OsRng);
            }

            let c4: PC = PC::new(d, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c1.comm, &c2.comm, &c4.comm));
        }

        #[test]
        fn test_pedersen_mul_nist() {
            // Test that the mul proof goes through.
            let label = b"PedersenMul";

            let a_t = OSF::rand(&mut OsRng);
            let b_t = OSF::rand(&mut OsRng);

            let a = <$config as PedersenConfig>::from_oc(a_t);
            let b = <$config as PedersenConfig>::from_oc(b_t);

            let z = a * b;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = MP::create(&mut transcript, &mut OsRng, &a, &b, &c1, &c2, &c3);
            assert!(proof.alpha.is_on_curve());
            assert!(proof.beta.is_on_curve());
            assert!(proof.delta.is_on_curve());

            // Now check that the proof verifies.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm, &c2.comm, &c3.comm));

            // And now check it would fail on a different c3 value.

            let mut d = SF::rand(&mut OsRng);

            loop {
                if d != z {
                    break;
                }
                d = SF::rand(&mut OsRng);
            }

            let c4: PC = PC::new(d, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c1.comm, &c2.comm, &c4.comm));
        }

        #[test]
        fn test_pedersen_point_add() {
            // Test that the point addition proof goes through.
            let label = b"PedersenECPointAdd";
            let a = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            let mut b = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();

            loop {
                if b != a {
                    break;
                }
                b = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            }

            // Note: this needs to be forced into affine too, or the underlying
            // proof system breaks (this seems to be an ark_ff thing).
            let t = (a + b).into_affine();

            let mut transcript = Transcript::new(label);
            let proof: EPAP<Config> = EPAP::create(&mut transcript, &mut OsRng, a, b, t);

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
            let mut tf = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            loop {
                if tf != t {
                    break;
                }
                tf = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            }

            // Now show it fails.
            let mut transcript_f1 = Transcript::new(label);
            let proof_f: EPAP<Config> = EPAP::create(&mut transcript_f1, &mut OsRng, a, b, tf);

            let mut transcript_f2 = Transcript::new(label);
            assert!(!proof_f.verify(&mut transcript_f2));
        }

        #[test]
        fn test_zkattest_point_add() {
            // Test that ZKAttest point addition proofs work.
            let label = b"PedersenZKAttestECPointAdd";
            let a = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            let mut b = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();

            loop {
                if b != a {
                    break;
                }
                b = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            }

            // Note: this needs to be forced into affine too, or the underlying
            // proof system breaks (this seems to be an ark_ff thing).
            let t = (a + b).into_affine();
            let mut transcript = Transcript::new(label);
            let proof: ZKEPAP<Config> = ZKEPAP::create(&mut transcript, &mut OsRng, a, b, t);

            // Check that all of the commitments are valid.
            assert!(proof.c1.is_on_curve());
            assert!(proof.c2.is_on_curve());
            assert!(proof.c3.is_on_curve());
            assert!(proof.c4.is_on_curve());
            assert!(proof.c5.is_on_curve());
            assert!(proof.c6.is_on_curve());
            assert!(proof.c8.is_on_curve());
            assert!(proof.c10.is_on_curve());
            assert!(proof.c11.is_on_curve());
            assert!(proof.c13.is_on_curve());

            // Now check that it verifies properly.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v));

            // Now check that an incorrect proof fails.
            let mut t2 = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            loop {
                if t2 != t {
                    break;
                }
                t2 = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            }

            // Make the false proof.
            let mut transcript_f = Transcript::new(label);
            let proof_f: ZKEPAP<Config> = ZKEPAP::create(&mut transcript_f, &mut OsRng, a, b, t2);

            // The rest of the invariants still hold.
            assert!(proof_f.c1.is_on_curve());
            assert!(proof_f.c2.is_on_curve());
            assert!(proof_f.c3.is_on_curve());
            assert!(proof_f.c4.is_on_curve());
            assert!(proof_f.c5.is_on_curve());
            assert!(proof_f.c6.is_on_curve());
            assert!(proof_f.c8.is_on_curve());
            assert!(proof_f.c10.is_on_curve());
            assert!(proof_f.c11.is_on_curve());
            assert!(proof_f.c13.is_on_curve());

            // And now check it fails.
            let mut transcript_fv = Transcript::new(label);
            assert!(!proof_f.verify(&mut transcript_fv));
        }

        #[test]
        fn test_scalar_mult() {
            // Test that scalar multiplication works.
            let label = b"PedersenScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();

            let mut transcript = Transcript::new(label);
            let proof: ECSMP<Config> =
                ECSMP::create(&mut transcript, &mut OsRng, &s, &lambda, &OGENERATOR);

            assert!(proof.c1.is_on_curve());
            assert!(proof.c2.is_on_curve());
            assert!(proof.c3.is_on_curve());
            assert!(proof.c4.is_on_curve());
            assert!(proof.c5.is_on_curve());
            assert!(proof.c6.is_on_curve());
            assert!(proof.c7.is_on_curve());
            assert!(proof.c8.is_on_curve());

            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &OGENERATOR));
        }
    };
}

#[macro_export]
macro_rules! test_pedersen {
    ($mod_name: ident; $config: ty, $OtherProjectiveType: ty) => {
        mod $mod_name {
            use super::*;
            use ark_ec::{
                models::CurveConfig,
                short_weierstrass::{self as sw, SWCurveConfig},
                AffineRepr, CurveGroup,
            };
            use ark_std::UniformRand;
            use core::ops::Mul;
            use merlin::Transcript;
            use pedersen::{
                ec_point_add_protocol::ECPointAddProof as EPAP,
                equality_protocol::EqualityProof as EP, mul_protocol::MulProof as MP,
                opening_protocol::OpeningProof as OP, pedersen_config::PedersenComm,
                pedersen_config::PedersenConfig, scalar_mul_proof::ECScalarMulProof as ECSMP,
                zk_attest_point_add_protocol::ZKAttestPointAddProof as ZKEPAP,
            };
            use rand_core::OsRng;
            $crate::__test_pedersen!($config, $OtherProjectiveType);
        }
    };
}