#[macro_export]
#[doc(hidden)]

macro_rules! __test_pedersen {
    ($config: ty, $OtherProjectiveType: ty) => {
        type PC = PedersenComm<$config>;
        type SF = <$config as CurveConfig>::ScalarField;
        type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;

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
            assert!(proof.verify(&mut transcript_v, &c1, &c2));

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
            assert!(!proof.verify(&mut transcript_f, &c1, &c3));
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
            assert!(proof.verify(&mut transcript_v, &c1, &c2));

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
            assert!(!proof.verify(&mut transcript_f, &c1, &c3));
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
            assert!(proof.verify(&mut transcript_v, &c1));

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
            assert!(!proof.verify(&mut transcript_f, &c3));
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
            assert!(proof.verify(&mut transcript_v, &c1));

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
            assert!(!proof.verify(&mut transcript_f, &c3));
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
            assert!(proof.verify(&mut transcript_v, &c1, &c2, &c3));

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
            assert!(!proof.verify(&mut transcript_f, &c1, &c2, &c4));
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
            assert!(proof.verify(&mut transcript_v, &c1, &c2, &c3));

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
            assert!(!proof.verify(&mut transcript_f, &c1, &c2, &c4));
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
            let proof: EPAP<Config> =
                EPAP::create(&mut transcript, &mut OsRng, a.x, a.y, b.x, b.y, t.x, t.y);

            assert!(proof.c1.comm.is_on_curve());
            assert!(proof.c2.comm.is_on_curve());
            assert!(proof.c3.comm.is_on_curve());
            assert!(proof.c4.comm.is_on_curve());
            assert!(proof.c5.comm.is_on_curve());
            assert!(proof.c6.comm.is_on_curve());
            assert!(proof.c7.comm.is_on_curve());

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
            let proof_f: EPAP<Config> = EPAP::create(
                &mut transcript_f1,
                &mut OsRng,
                a.x,
                a.y,
                b.x,
                b.y,
                tf.x,
                tf.y,
            );

            let mut transcript_f2 = Transcript::new(label);
            assert!(!proof_f.verify(&mut transcript_f2));
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
                short_weierstrass::{self as sw},
                AffineRepr, CurveGroup,
            };
            use ark_std::UniformRand;
            use merlin::Transcript;
            use pedersen::{
                ec_point_add_protocol::ECPointAddProof as EPAP,
                equality_protocol::EqualityProof as EP, mul_protocol::MulProof as MP,
                opening_protocol::OpeningProof as OP, pedersen_config::PedersenComm,
                pedersen_config::PedersenConfig,
            };
            use rand_core::OsRng;
            $crate::__test_pedersen!($config, $OtherProjectiveType);
        }
    };
}
