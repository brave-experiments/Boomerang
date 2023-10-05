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

            // We now commit to t, a, b.
            let (cax, cay, cbx, cby, ctx, cty) =
                <$config as PedersenConfig>::create_commitments_to_coords(a, b, t, &mut OsRng);
            let mut transcript = Transcript::new(label);
            let proof = EPAP::<$config>::create_with_existing_commitments(
                &mut transcript,
                &mut OsRng,
                a,
                b,
                t,
                &cax,
                &cay,
                &cbx,
                &cby,
                &ctx,
                &cty,
            );
            assert!(proof.c7.is_on_curve());

            // Now check that it verifies.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(
                &mut transcript_v,
                &cax.comm,
                &cay.comm,
                &cbx.comm,
                &cby.comm,
                &ctx.comm,
                &cty.comm
            ));

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
            let (caxf, cayf, cbxf, cbyf, ctxf, ctyf) =
                <$config as PedersenConfig>::create_commitments_to_coords(a, b, tf, &mut OsRng);
            let proof_f: EPAP<Config> = EPAP::<$config>::create_with_existing_commitments(
                &mut transcript_f1,
                &mut OsRng,
                a,
                b,
                tf,
                &caxf,
                &cayf,
                &cbxf,
                &cbyf,
                &ctxf,
                &ctyf,
            );

            let mut transcript_f2 = Transcript::new(label);
            assert!(!proof_f.verify(
                &mut transcript_f2,
                &caxf.comm,
                &cayf.comm,
                &cbxf.comm,
                &cbyf.comm,
                &ctxf.comm,
                &ctyf.comm
            ));
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
            // We now commit to t, a, b.
            let (cax, cay, cbx, cby, ctx, cty) =
                <$config as PedersenConfig>::create_commitments_to_coords(a, b, t, &mut OsRng);

            let proof = ZKEPAP::<$config>::create_with_existing_commitments(
                &mut transcript,
                &mut OsRng,
                a,
                b,
                t,
                &cax,
                &cay,
                &cbx,
                &cby,
                &ctx,
                &cty,
            );

            // Check that all of the commitments are valid.
            assert!(proof.c8.is_on_curve());
            assert!(proof.c10.is_on_curve());
            assert!(proof.c11.is_on_curve());
            assert!(proof.c13.is_on_curve());

            // Now check that it verifies properly.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(
                &mut transcript_v,
                &cax.comm,
                &cay.comm,
                &cbx.comm,
                &cby.comm,
                &ctx.comm,
                &cty.comm
            ));

            // Now check that an incorrect proof fails.
            let mut t2 = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            loop {
                if t2 != t {
                    break;
                }
                t2 = <$OtherProjectiveType>::rand(&mut OsRng).into_affine();
            }

            // Make the false proof.
            let ct2x = <$config as PedersenConfig>::make_commitment_from_other(t2.x, &mut OsRng);
            let ct2y = <$config as PedersenConfig>::make_commitment_from_other(t2.y, &mut OsRng);
            let mut transcript_f = Transcript::new(label);
            let proof_f = ZKEPAP::<$config>::create_with_existing_commitments(
                &mut transcript_f,
                &mut OsRng,
                a,
                b,
                t2,
                &cax,
                &cay,
                &cbx,
                &cby,
                &ct2x,
                &ct2y,
            );

            // The rest of the invariants still hold.
            assert!(proof_f.c8.is_on_curve());
            assert!(proof_f.c10.is_on_curve());
            assert!(proof_f.c11.is_on_curve());
            assert!(proof_f.c13.is_on_curve());

            // And now check it fails.
            let mut transcript_fv = Transcript::new(label);
            assert!(!proof_f.verify(
                &mut transcript_fv,
                &cax.comm,
                &cay.comm,
                &cbx.comm,
                &cby.comm,
                &ct2x.comm,
                &ct2y.comm
            ));
        }

        #[test]
        fn test_scalar_mult() {
            // Test that scalar multiplication works.
            let label = b"PedersenScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();

            let mut transcript = Transcript::new(label);

            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let inter = ECSMP::<$config>::create_intermediates_with_existing_commitments(
                &mut transcript,
                &mut OsRng,
                &s,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2,
                &c3,
            );
            assert!(inter.c4.is_on_curve());
            assert!(inter.c5.comm.is_on_curve());
            assert!(inter.c6.comm.is_on_curve());
            assert!(inter.c7.comm.is_on_curve());
            assert!(inter.c8.comm.is_on_curve());

            let chal = ECSMP::<$config>::challenge_scalar(&mut transcript);
            let proof = ECSMP::<$config>::create_proof(
                &s,
                &lambda,
                &OGENERATOR,
                &inter,
                &chal,
                &c1,
                &r1,
                &c2,
                &c3,
            );
            assert!(proof.c4.is_on_curve());
            assert!(proof.c5.is_on_curve());
            assert!(proof.c6.is_on_curve());
            assert!(proof.c7.is_on_curve());
            assert!(proof.c8.is_on_curve());

            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &OGENERATOR, &c1, &c2.comm, &c3.comm));

            // Now make a fake transcript.
            let s_fake = (OGENERATOR.mul(lambda) + OGENERATOR).into_affine();
            let c2f = PC::new(
                <$config as PedersenConfig>::from_ob_to_sf(s_fake.x),
                &mut OsRng,
            );
            let c3f = PC::new(
                <$config as PedersenConfig>::from_ob_to_sf(s_fake.y),
                &mut OsRng,
            );

            let mut transcript_f = Transcript::new(label);
            let inter_f = ECSMP::<$config>::create_intermediates_with_existing_commitments(
                &mut transcript,
                &mut OsRng,
                &s,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2f,
                &c3f,
            );
            let chalf = ECSMP::<$config>::challenge_scalar(&mut transcript_f);
            let proof_f = ECSMP::<$config>::create_proof(
                &s_fake,
                &lambda,
                &OGENERATOR,
                &inter,
                &chalf,
                &c1,
                &r1,
                &c2f,
                &c3f,
            );

            // All of the other invariants are right.
            assert!(proof_f.c4.is_on_curve());
            assert!(proof_f.c5.is_on_curve());
            assert!(proof_f.c6.is_on_curve());
            assert!(proof_f.c7.is_on_curve());
            assert!(proof_f.c8.is_on_curve());

            // But the verification fails.
            let mut transcript_fv = Transcript::new(label);
            assert!(!proof_f.verify(&mut transcript_fv, &OGENERATOR, &c1, &c2f.comm, &c3f.comm));
        }

        #[test]
        fn test_fs_ec_scalar_mult() {
            // Test that the Fiat-Shamir scalar multiplication works.
            let label = b"PedersenFSScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let mut transcript = Transcript::new(label);

            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let proof: FSECMP<Config, ECSMP<Config>> = FSECMP::create(
                &mut transcript,
                &mut OsRng,
                &s,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2,
                &c3,
            );

            // Check it passes.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &OGENERATOR, &c1, &c2.comm, &c3.comm));

            // Now make a fake transcript.
            let s_fake = (OGENERATOR.mul(lambda) + OGENERATOR).into_affine();
            let c2f = PC::new(
                <$config as PedersenConfig>::from_ob_to_sf(s_fake.x),
                &mut OsRng,
            );
            let c3f = PC::new(
                <$config as PedersenConfig>::from_ob_to_sf(s_fake.y),
                &mut OsRng,
            );

            let mut transcript_f = Transcript::new(label);

            let proof_f: FSECMP<Config, ECSMP<Config>> = FSECMP::create(
                &mut transcript_f,
                &mut OsRng,
                &s_fake,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2f,
                &c3f,
            );
            let mut transcript_fv = Transcript::new(label);
            assert!(!proof_f.verify(&mut transcript_fv, &OGENERATOR, &c1, &c2f.comm, &c3f.comm));
        }

        #[test]
        fn test_zk_attest_scalar_mult() {
            // Test that the ZKAttest scalar multiplication proof goes through.
            let label = b"PedersenZkAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let mut transcript = Transcript::new(label);
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let inter = ZKECSMP::<$config>::create_intermediates_with_existing_commitments(
                &mut transcript,
                &mut OsRng,
                &s,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2,
                &c3,
            );
            assert!(inter.c4.comm.is_on_curve());
            assert!(inter.c5.comm.is_on_curve());
            assert!(inter.a1.is_on_curve());
            assert!(inter.a2.comm.is_on_curve());
            assert!(inter.a3.comm.is_on_curve());

            let chal = ZKECSMP::<$config>::challenge_scalar(&mut transcript);
            let proof = ZKECSMP::<$config>::create_proof(
                &s,
                &lambda,
                &OGENERATOR,
                &inter,
                &chal,
                &c1,
                &r1,
                &c2,
                &c3,
            );

            // Check everything lies on the curve.
            assert!(proof.c4.is_on_curve());
            assert!(proof.c5.is_on_curve());
            assert!(proof.a1.is_on_curve());
            assert!(proof.a2.is_on_curve());
            assert!(proof.a3.is_on_curve());

            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &OGENERATOR, &c1, &c2.comm, &c3.comm));
        }

        #[test]
        fn test_fs_zk_ec_scalar_mult() {
            // Test that the Fiat-Shamir scalar multiplication works.
            let label = b"PedersenFsZkAttestScalarMult";

            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let mut transcript = Transcript::new(label);

            let proof: FSECMP<Config, ZKECSMP<Config>> = FSECMP::create(
                &mut transcript,
                &mut OsRng,
                &s,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2,
                &c3,
            );

            // Check it passes.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &OGENERATOR, &c1, &c2.comm, &c3.comm));

            // Now make a fake transcript.
            let s_fake = (OGENERATOR.mul(lambda) + OGENERATOR).into_affine();
            let c2f = PC::new(
                <$config as PedersenConfig>::from_ob_to_sf(s_fake.x),
                &mut OsRng,
            );
            let c3f = PC::new(
                <$config as PedersenConfig>::from_ob_to_sf(s_fake.y),
                &mut OsRng,
            );
            let mut transcript_f = Transcript::new(label);

            let proof_f: FSECMP<Config, ZKECSMP<Config>> = FSECMP::create(
                &mut transcript_f,
                &mut OsRng,
                &s_fake,
                &lambda,
                &OGENERATOR,
                &c1,
                &r1,
                &c2f,
                &c3f,
            );
            let mut transcript_fv = Transcript::new(label);
            assert!(!proof_f.verify(&mut transcript_fv, &OGENERATOR, &c1, &c2f.comm, &c3f.comm));
        }

        #[test]
        fn test_gk_zero_one_zero() {
            // Test that the GK zero-one proof works on a value of 0.
            let label = b"PedersenZeroOne";
            let m = SF::ZERO;
            let c: PC = PC::new(m, &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(label);
            let proof: ZOP<Config> = ZOP::create(&mut transcript, &mut OsRng, &m, &c);

            // Now check the proof is fine.
            assert!(proof.ca.is_on_curve());
            assert!(proof.cb.is_on_curve());

            // And now check that it passes.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c.comm));

            // Check that it would fail on a commitment to one.
            let n = SF::ONE;
            let cf: PC = PC::new(n, &mut OsRng);
            transcript_v = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_v, &cf.comm));
        }

        fn make_ecdsa_signature(z: &OSF, private: &OSF) -> (OSF, OSF) {
            loop {
                // First we begin the process of making `r`.
                let k = OSF::rand(&mut OsRng);

                // We require that `k` is invertible.
                if k == OSF::ZERO {
                    continue;
                }

                let kG = OGENERATOR.mul(k).into_affine();
                let r = <$config as PedersenConfig>::from_ob_to_os(kG.x);

                // Repeat until we have a decent value of `r`.
                if r == OSF::ZERO {
                    continue;
                }

                // Now make s.
                let s = (k.inverse().unwrap()) * (*z + private.mul(&r));
                if s == OSF::ZERO {
                    continue;
                }

                return (r, s);
            }
        }

        #[test]
        fn test_ecdsa_signature_our() {
            // This function just tests that we can prove knowledge of an ECDSA signature.
            let label = b"PedersenECDSA";

            // Make the public key.
            let private = OSF::rand(&mut OsRng);
            let public = OGENERATOR.mul(private).into_affine();

            // For the sake of this test, we'll use the simplest message in existence.
            let m = b"";

            // And now we begin the long and arduous process of making a signature.
            // N.B For the sake of compatibility, we always use SHA-512 here and just truncate.
            let mut hasher = Sha512::new();
            hasher.update(m);
            let h = hasher.finalize();

            // We map `t` to the curve by using the `from_random_bytes` API.
            let t = OSF::from_random_bytes(&h[0..32]).unwrap();

            // Build the signature.
            let (r, s) = make_ecdsa_signature(&t, &private);

            // Now we need to make `R`.
            let u1 = t * s.inverse().unwrap();
            let u2 = r * s.inverse().unwrap();

            let R = (OGENERATOR.mul(u1) + public.mul(u2)).into_affine();
            assert!(<$config>::from_ob_to_os(R.x) == r);

            // Now prove it passed.
            let mut transcript = Transcript::new(label);

            let proof = ECDSASigProof::<$config, CDLSCollective>::create(
                &mut transcript,
                &mut OsRng,
                &t,
                &R,
                &r,
                &s,
                &public,
            );
            assert!(proof.r.is_on_curve());
            assert!(proof.cq_x.is_on_curve());
            assert!(proof.cq_y.is_on_curve());
            assert!(proof.cs_x.is_on_curve());
            assert!(proof.cs_y.is_on_curve());

            // Now check it passes verification.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &R, &t));

            // Finally, check that it would fail on a different choice of &R.
            let Rf = (R + OGENERATOR).into_affine();
            let mut transcript_vf = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_vf, &Rf, &t));
        }

        #[test]
        fn test_ecdsa_signature_zk_attest() {
            // This function just tests that we can prove knowledge of an ECDSA signature using
            // ZKAttest.
            let label = b"PedersenECDSA";

            // Make the public key.
            let private = OSF::rand(&mut OsRng);
            let public = OGENERATOR.mul(private).into_affine();

            // For the sake of this test, we'll use the simplest message in existence.
            let m = b"";

            // And now we begin the long and arduous process of making a signature.
            // N.B For the sake of compatibility, we always use SHA-512 here and just truncate.
            let mut hasher = Sha512::new();
            hasher.update(m);
            let h = hasher.finalize();

            // We map `t` to the curve by using the `from_random_bytes` API.
            let t = OSF::from_random_bytes(&h[0..32]).unwrap();

            // Build the signature.
            let (r, s) = make_ecdsa_signature(&t, &private);

            // Now we need to make `R`.
            let u1 = t * s.inverse().unwrap();
            let u2 = r * s.inverse().unwrap();

            let R = (OGENERATOR.mul(u1) + public.mul(u2)).into_affine();
            assert!(<$config>::from_ob_to_os(R.x) == r);

            // Now prove it passed.
            let mut transcript = Transcript::new(label);

            let proof = ECDSASigProof::<$config, ZKAttestCollective>::create(
                &mut transcript,
                &mut OsRng,
                &t,
                &R,
                &r,
                &s,
                &public,
            );
            assert!(proof.r.is_on_curve());
            assert!(proof.cq_x.is_on_curve());
            assert!(proof.cq_y.is_on_curve());
            assert!(proof.cs_x.is_on_curve());
            assert!(proof.cs_y.is_on_curve());

            // Now check it passes verification.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &R, &t));

            // Finally, check that it would fail on a different choice of &R.
            let Rf = (R + OGENERATOR).into_affine();
            let mut transcript_vf = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_vf, &Rf, &t));
        }

        #[test]
        fn test_gk_zero_one_one() {
            // Test that the GK zero-one proof works on a value of 1.
            let label = b"PedersenZeroOne";
            let m = SF::ONE;
            let c: PC = PC::new(m, &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(label);
            let proof: ZOP<Config> = ZOP::create(&mut transcript, &mut OsRng, &m, &c);

            // Now check the proof is fine.
            assert!(proof.ca.is_on_curve());
            assert!(proof.cb.is_on_curve());

            // And now check that it passes.
            let mut transcript_v = Transcript::new(label);
            assert!(proof.verify(&mut transcript_v, &c.comm));

            // Check that it would fail on a commitment to zero.
            let n = SF::ZERO;
            let cf: PC = PC::new(n, &mut OsRng);
            transcript_v = Transcript::new(label);
            assert!(!proof.verify(&mut transcript_v, &cf.comm));
        }

        #[test]
        fn test_interpolation() {
            // Test that the polynomial interpolation works.
            // Simple case: y = 3x.
            {
                let x: [SF; 2] = [SF::ZERO, SF::ONE];
                let y: [SF; 2] = [SF::ZERO, <$config>::from_u64_to_sf(3)];
                let coeffs = PolynomialInterpolation::<$config>::interpolate(&x, &y);
                assert!(coeffs.len() == 2);
                assert!(coeffs[0] == SF::ZERO);
                assert!(coeffs[1] == <$config>::from_u64_to_sf(3));
            }

            // More complicated case: y = 3x^2 + x + 1.
            {
                let x: [SF; 3] = [SF::ZERO, SF::ONE, SF::ONE + SF::ONE];
                let y: [SF; 3] = [
                    SF::ONE,
                    <$config>::from_u64_to_sf(5),
                    <$config>::from_u64_to_sf(15),
                ];

                let coeffs = PolynomialInterpolation::<$config>::interpolate(&x, &y);
                assert!(coeffs.len() == 3);
                assert!(coeffs[0] == SF::ONE);
                assert!(coeffs[1] == SF::ONE);
                assert!(coeffs[2] == <$config>::from_u64_to_sf(3));
            }

            // And even more: this time, y = x^4 + x^2 + 1.
            {
                let mut x: [SF; 5] = [SF::ZERO, SF::ZERO, SF::ZERO, SF::ZERO, SF::ZERO];
                let mut y: [SF; 5] = [SF::ZERO, SF::ZERO, SF::ZERO, SF::ZERO, SF::ZERO];

                for i in 0..5 {
                    x[i] = <$config>::from_u64_to_sf(i as u64);
                    y[i] = (x[i] * x[i] * x[i] * x[i]) + (x[i] * x[i]) + SF::ONE;
                }

                let coeffs = PolynomialInterpolation::<$config>::interpolate(&x, &y);
                assert!(coeffs.len() == 5);
                assert!(coeffs[0] == coeffs[2] && coeffs[2] == coeffs[4] && coeffs[4] == SF::ONE);
                assert!(coeffs[1] == coeffs[3] && coeffs[3] == SF::ZERO);
            }
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
            use core::ops::Mul;
            use merlin::Transcript;
            use pedersen::{
                ec_collective::CDLSCollective,
                ec_point_add_protocol::{ECPointAddIntermediate as EPAI, ECPointAddProof as EPAP},
                ecdsa_protocol::ECDSASigProof,
                equality_protocol::EqualityProof as EP,
                fs_scalar_mul_protocol::FSECScalarMulProof as FSECMP,
                gk_zero_one_protocol::{ZeroOneProof as ZOP, ZeroOneProofIntermediate as ZOPI},
                interpolate::PolynomialInterpolation,
                mul_protocol::MulProof as MP,
                opening_protocol::OpeningProof as OP,
                pedersen_config::PedersenComm,
                pedersen_config::PedersenConfig,
                point_add::PointAddProtocol,
                scalar_mul::ScalarMulProtocol,
                scalar_mul_protocol::{
                    ECScalarMulProof as ECSMP, ECScalarMulProofIntermediate as ECSMPI,
                },
                zk_attest_collective::ZKAttestCollective,
                zk_attest_point_add_protocol::{
                    ZKAttestPointAddProof as ZKEPAP, ZKAttestPointAddProofIntermediate as ZKEPAPI,
                },
                zk_attest_scalar_mul_protocol::{
                    ZKAttestECScalarMulProof as ZKECSMP,
                    ZKAttestECScalarMulProofIntermediate as ZKECSMPI,
                },
            };
            use rand_core::OsRng;
            use sha2::{Digest, Sha512};
            $crate::__test_pedersen!($config, $OtherProjectiveType);
        }
    };
}
