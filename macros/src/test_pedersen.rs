#[macro_export]
#[doc(hidden)]

macro_rules! __test_pedersen {
    ($config: ty, $OtherProjectiveType: ty) => {
        type PC = PedersenComm<$config>;
        type SF = <$config as CurveConfig>::ScalarField;
        type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
        type OSA = sw::Affine<<$config as PedersenConfig>::OCurve>;
        type AT = sw::Affine<$config>;

        const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
            <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

        fn make_challenge(x: &SF) -> Vec<u8> {
            let mut compressed_bytes = Vec::new();
            x.serialize_compressed(&mut compressed_bytes).unwrap();
            compressed_bytes
        }

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

            let c_act: AT = (c1.comm.into_group() - c2.comm).into();
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
        fn test_pedersen_equality_other_challenge() {
            // Test that the equality proof fails if the wrong challenge is used.
            let label = b"PedersenEq";
            let a = OSF::rand(&mut OsRng);
            let c1: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);
            let c2: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);

            let mut transcript = Transcript::new(label);

            // Build the proof.
            let proof_i = EP::create_intermediates(&mut transcript, &mut OsRng, &c1, &c2);

            // Now we pre-specify the challenge to be the CM1 point.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            // Pass that challenge into the create_proof function.
            let proof = EP::create_proof(&proof_i, &c1, &c2, &c[..]);

            assert!(proof.alpha.is_on_curve());

            // Check that the proof passes with the same challenge.
            assert!(proof.verify_proof(&c1.comm, &c2.comm, &c[..]));

            // But that it fails with the other.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &c2.comm, &cf[..]));
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
        fn test_pedersen_equality_nist_other_challenge() {
            // Test that the equality proof fails if the wrong challenge is used.
            // Test that the equality proof fails if the wrong challenge is used.
            let label = b"PedersenEq";

            let a = OSF::rand(&mut OsRng);
            let c1: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);
            let c2: PC = PC::new(<$config as PedersenConfig>::from_oc(a), &mut OsRng);

            let mut transcript = Transcript::new(label);

            // Build the proof.
            let proof_i = EP::create_intermediates(&mut transcript, &mut OsRng, &c1, &c2);

            // Now we pre-specify the challenge to be the CM1 point.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            // Pass that challenge into the create_proof function.
            let proof = EP::create_proof(&proof_i, &c1, &c2, &c[..]);

            assert!(proof.alpha.is_on_curve());

            // Check that the proof passes with the same challenge.
            assert!(proof.verify_proof(&c1.comm, &c2.comm, &c[..]));

            // But that it fails with the other.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &c2.comm, &cf[..]));
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
        fn test_pedersen_multi_comm() {
            // Test that creating multi commitments goes through.
            let label = b"PedersenOpenMulti";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(&vals, &mut OsRng);
            let mut transcript = Transcript::new(label);
        }

        #[test]
        fn test_pedersen_multi_comm_opening() {
            // Test that the opening proof with multi commitments goes through.
            let label = b"PedersenOpenMulti";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(&vals, &mut OsRng);
            let mut transcript = Transcript::new(label);

            let proof = OPM::create(&mut transcript, &mut OsRng, &vals, &c1, &gens);
            assert!(proof.alpha.is_on_curve());

            // Now check that the proof verifies correctly.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm, vals.len(), &gens));
        }

        #[test]
        fn test_pedersen_multi_comm_issuance() {
            // Test that the issuance proof with multi commitments goes through.
            let label = b"PedersenIssuanceMulti";

            let a = SF::rand(&mut OsRng);
            let b = SF::zero(); // zero
            let lambda = SF::rand(&mut OsRng); // pk
            let d = SF::rand(&mut OsRng);
            let e = SF::rand(&mut OsRng);

            let gen = PC::get_main_generator();
            let pk = gen.mul(lambda).into_affine();

            let mut vals: Vec<SF> = Vec::new();
            vals.push(a);
            vals.push(b);
            vals.push(lambda);
            vals.push(d);
            vals.push(e);

            let (c1, gens) = PC::new_multi(&vals, &mut OsRng);
            let mut transcript = Transcript::new(label);

            let proof = IPM::create(&mut transcript, &mut OsRng, &vals, &c1, &gens);
            assert!(proof.alpha.is_on_curve());

            // Now check that the proof verifies correctly.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm, &pk, vals.len(), &gens));
        }

        #[test]
        fn test_pedersen_opening_other_challenge() {
            // Test that the proof fails if the wrong challenge is used.
            let label = b"PedersenOpen";

            let a = SF::rand(&mut OsRng);
            let c1: PC = PC::new(a, &mut OsRng);
            let mut transcript = Transcript::new(label);

            let proof_i = OP::create_intermediates(&mut transcript, &mut OsRng, &c1);

            // Specify the challenge.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            let proof = OP::create_proof(&a, &proof_i, &c1, &c[..]);
            assert!(proof.alpha.is_on_curve());

            // Now check that the proof verifies correctly.
            assert!(proof.verify_proof(&c1.comm, &c[..]));

            // And now check that it fails on a different challenge.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &cf[..]));
        }

        //#[test]
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
        fn test_pedersen_opening_nist_other_challenge() {
            // Test that the proof does not verify if the challenge is changed.
            let label = b"PedersenOpen";

            let a_t = OSF::rand(&mut OsRng);
            let a = <$config as PedersenConfig>::from_oc(a_t);
            let c1: PC = PC::new(a, &mut OsRng);

            let mut transcript = Transcript::new(label);

            let proof_i = OP::create_intermediates(&mut transcript, &mut OsRng, &c1);

            // Specify the challenge.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            let proof = OP::create_proof(&a, &proof_i, &c1, &c[..]);
            assert!(proof.alpha.is_on_curve());

            // Now check that the proof verifies correctly.
            assert!(proof.verify_proof(&c1.comm, &c[..]));

            // And now check that it fails on a different challenge.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &cf[..]));
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
        fn test_pedersen_mul_other_challenge() {
            // Check that the mul proof fails if the wrong challenge is used.
            // Test that the mul proof goes through.
            let label = b"PedersenMul";

            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let z = a * b;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);

            let mut transcript = Transcript::new(label);

            let proof_i = MP::create_intermediates(&mut transcript, &mut OsRng, &c1, &c2, &c3);

            // Now we pre-specify the challenge to be the CM1 point.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            let proof = MP::create_proof(&a, &b, &proof_i, &c1, &c2, &c3, &c[..]);
            assert!(proof.alpha.is_on_curve());
            assert!(proof.beta.is_on_curve());
            assert!(proof.delta.is_on_curve());

            // Now check that the proof verifies on the same challenge.
            assert!(proof.verify_proof(&c1.comm, &c2.comm, &c3.comm, &c[..]));

            // And that it fails on the other one.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &c2.comm, &c3.comm, &cf[..]));
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
        fn test_pedersen_mul_nist_other_challenge() {
            // Check that the mul proof fails if the wrong challenge is used.
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

            let proof_i = MP::create_intermediates(&mut transcript, &mut OsRng, &c1, &c2, &c3);

            // Now we pre-specify the challenge to be the CM1 point.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            let proof = MP::create_proof(&a, &b, &proof_i, &c1, &c2, &c3, &c[..]);
            assert!(proof.alpha.is_on_curve());
            assert!(proof.beta.is_on_curve());
            assert!(proof.delta.is_on_curve());

            // Now check that the proof verifies on the same challenge.
            assert!(proof.verify_proof(&c1.comm, &c2.comm, &c3.comm, &c[..]));

            // And that it fails on the other one.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &c2.comm, &c3.comm, &cf[..]));
        }

        #[test]
        fn test_pedersen_add_mul() {
            // Test that the add-mul proof goes through.
            let label = b"PedersenAddMul";

            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let w = a * b;
            let t = w + c;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(c, &mut OsRng);
            let c4: PC = PC::new(w, &mut OsRng);
            let c5: PC = c4 + c3;

            let mut transcript = Transcript::new(label);
            let proof = AMP::create(
                &mut transcript,
                &mut OsRng,
                &a,
                &b,
                &c,
                &c1,
                &c2,
                &c3,
                &c4,
                &c5,
            );
            assert!(proof.t1.is_on_curve());
            assert!(proof.t2.is_on_curve());
            assert!(proof.t3.is_on_curve());
            assert!(proof.t4.is_on_curve());
            assert!(proof.t5.is_on_curve());

            // Now check that the proof verifies.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(
                &mut transcript_v,
                &c1.comm,
                &c2.comm,
                &c3.comm,
                &c4.comm,
                &c5.comm
            ));

            // And now check it would fail on a different c5 value.

            let mut d = SF::rand(&mut OsRng);

            loop {
                if d != t {
                    break;
                }
                d = SF::rand(&mut OsRng);
            }

            let c5: PC = PC::new(d, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(
                &mut transcript_f,
                &c1.comm,
                &c2.comm,
                &c3.comm,
                &c4.comm,
                &c5.comm
            ));
        }

        #[test]
        fn test_pedersen_non_zero() {
            // Test that the non-zero proof goes through.
            let label = b"PedersenNonZero";

            let x = SF::rand(&mut OsRng);

            let c1: PC = PC::new(x, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = NZP::create(&mut transcript, &mut OsRng, &x, &c1);
            assert!(proof.t1.is_on_curve());
            assert!(proof.t2.is_on_curve());
            assert!(proof.t3.is_on_curve());

            // Now check that the proof verifies.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm));

            // And now check it would fail on a different c1 value.

            let mut d = SF::rand(&mut OsRng);

            loop {
                if d != x {
                    break;
                }
                d = SF::rand(&mut OsRng);
            }

            let c2: PC = PC::new(d, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c2.comm));
        }

        #[test]
        fn test_pedersen_non_zero_fail() {
            // Test that the non-zero proof does not go through.
            let label = b"PedersenNonZero";

            let x = SF::ZERO;

            let c1: PC = PC::new(x, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = NZP::create(&mut transcript, &mut OsRng, &x, &c1);
            assert!(proof.t1.is_on_curve());
            assert!(proof.t2.is_on_curve());
            assert!(proof.t3.is_on_curve());

            // Now check that the proof fails on verification.
            let mut transcript_v = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_v, &c1.comm));
            assert!(proof.t1 == sw::Affine::identity());
        }

        #[test]
        fn test_pedersen_non_zero_other_challenge() {
            // Check that the non-zero proof fails if the wrong challenge is used.
            // Test that the non-zero proof goes through.
            let label = b"PedersenNonZero";

            let x = SF::rand(&mut OsRng);

            let c1: PC = PC::new(x, &mut OsRng);

            let mut transcript = Transcript::new(label);

            let proof_i = NZP::create_intermediates(&mut transcript, &mut OsRng, &x, &c1);

            // Now we pre-specify the challenge to be the CM1 point.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            let proof = NZP::create_proof(&x, &proof_i, &c1, &c[..]);
            assert!(proof.t1.is_on_curve());
            assert!(proof.t2.is_on_curve());
            assert!(proof.t3.is_on_curve());

            // Now check that the proof verifies on the same challenge.
            assert!(proof.verify_proof(&c1.comm, &c[..]));

            // And that it fails on the other one.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &cf[..]));
        }

        #[test]
        fn test_pedersen_non_zero_nist() {
            // Test that the non-zero proof goes through.
            let label = b"PedersenNonZero";

            let x_t = OSF::rand(&mut OsRng);

            let x = <$config as PedersenConfig>::from_oc(x_t);

            let c1: PC = PC::new(x, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = NZP::create(&mut transcript, &mut OsRng, &x, &c1);
            assert!(proof.t1.is_on_curve());
            assert!(proof.t2.is_on_curve());
            assert!(proof.t3.is_on_curve());

            // Now check that the proof verifies.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c1.comm));

            // And now check it would fail on a different c1 value.

            let mut d = SF::rand(&mut OsRng);

            loop {
                if d != x {
                    break;
                }
                d = SF::rand(&mut OsRng);
            }

            let c2: PC = PC::new(d, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_f, &c2.comm));
        }

        #[test]
        fn test_pedersen_non_zero_nist_other_challenge() {
            // Check that the non-zero proof fails if the wrong challenge is used.
            // Test that the non-zero proof goes through.
            let label = b"PedersenMul";

            let x_t = OSF::rand(&mut OsRng);

            let x = <$config as PedersenConfig>::from_oc(x_t);

            let c1: PC = PC::new(x, &mut OsRng);

            let mut transcript = Transcript::new(label);

            let proof_i = NZP::create_intermediates(&mut transcript, &mut OsRng, &x, &c1);

            // Now we pre-specify the challenge to be the CM1 point.
            let c = make_challenge(&<$config as PedersenConfig>::CM1);

            let proof = NZP::create_proof(&x, &proof_i, &c1, &c[..]);
            assert!(proof.t1.is_on_curve());
            assert!(proof.t2.is_on_curve());
            assert!(proof.t3.is_on_curve());

            // Now check that the proof verifies on the same challenge.
            assert!(proof.verify_proof(&c1.comm, &c[..]));

            // And that it fails on the other one.
            let cf = make_challenge(&<$config as PedersenConfig>::CP1);
            assert!(!proof.verify_proof(&c1.comm, &cf[..]));
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
            use ark_ff::{Field, PrimeField};
            use ark_serialize::CanonicalSerialize;
            use ark_std::UniformRand;
            use ark_std::Zero;
            use core::ops::Mul;
            use merlin::Transcript;
            use pedersen::{
                add_mul_protocol::AddMulProof as AMP,
                ec_collective::CDLSCollective,
                ec_point_add_protocol::{ECPointAddIntermediate as EPAI, ECPointAddProof as EPAP},
                ecdsa_protocol::ECDSASigProof,
                equality_protocol::EqualityProof as EP,
                issuance_protocol::IssuanceProofMulti as IPM,
                mul_protocol::MulProof as MP,
                non_zero_protocol::NonZeroProof as NZP,
                opening_protocol::OpeningProof as OP,
                opening_protocol::OpeningProofMulti as OPM,
                pedersen_config::PedersenComm,
                pedersen_config::PedersenConfig,
                point_add::PointAddProtocol,
                product_protocol::ProductProof as PP,
            };
            use rand_core::OsRng;
            use sha2::{Digest, Sha512};
            $crate::__test_pedersen!($config, $OtherProjectiveType);
        }
    };
}
