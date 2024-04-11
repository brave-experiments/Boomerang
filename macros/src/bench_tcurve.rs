#[macro_export]
macro_rules! bench_tcurve_opening_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Sample a new random scalar.
            let x = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);

            // And commit to it.
            let com = PedersenComm::<$config>::new(x, &mut OsRng);

            // Now we can just benchmark how long it takes to create a new proof.
            c.bench_function(concat!($curve_name, " opening proof prover time"), |b| {
                b.iter(|| {
                    let mut transcript = Transcript::new(b"test-open");
                    OP::create(&mut transcript, &mut OsRng, &x, &com)
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_opening_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Sample a new random scalar.
            let x = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);

            // And commit to it.
            let com = PedersenComm::<$config>::new(x, &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(b"test-open");
            let proof = OP::create(&mut transcript, &mut OsRng, &x, &com);

            // And now just check how long it takes to open the proof.
            c.bench_function(concat!($curve_name, " opening proof verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(b"test-open");
                    proof.verify(&mut transcript_v, &com.comm);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_opening_multi_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Sample a new random scalars.
            let b = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let e = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let d = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let mut vals: Vec<<$config as CurveConfig>::ScalarField> = Vec::new();
            vals.push(b);
            vals.push(e);
            vals.push(d);

            // And commit to them.
            let (com, gens) = PedersenComm::<$config>::new_multi(vals.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(
                concat!($curve_name, " opening multi proof prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(b"test-open-multi");
                        OPM::create(
                            &mut transcript,
                            &mut OsRng,
                            vals.clone(),
                            &com,
                            gens.clone(),
                        )
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_opening_multi_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Sample a new random scalars.
            let b = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let e = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let d = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let mut vals: Vec<<$config as CurveConfig>::ScalarField> = Vec::new();
            vals.push(b);
            vals.push(e);
            vals.push(d);

            // And commit to them.
            let (com, gens) = PedersenComm::<$config>::new_multi(vals.clone(), &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(b"test-open-multi");
            let proof = OPM::create(
                &mut transcript,
                &mut OsRng,
                vals.clone(),
                &com,
                gens.clone(),
            );

            // And now just check how long it takes to verify the proof.
            c.bench_function(
                concat!($curve_name, " opening proof multi verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(b"test-open-multi");
                        proof.verify(&mut transcript_v, &com.comm, vals.len(), gens.clone());
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_issuance_multi_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Sample a new random scalars.
            let b = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let e = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let d = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let sk = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let mut vals: Vec<<$config as CurveConfig>::ScalarField> = Vec::new();
            vals.push(b);
            vals.push(e);
            vals.push(d);
            vals.push(sk);

            let gen = PedersenComm::<$config>::get_main_generator();
            let pk = gen.mul(sk).into_affine();

            // And commit to them.
            let (com, gens) = PedersenComm::<$config>::new_multi(vals.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(
                concat!($curve_name, " issuance multi proof prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(b"test-issue-multi");
                        IPM::create(
                            &mut transcript,
                            &mut OsRng,
                            vals.clone(),
                            &com,
                            gens.clone(),
                        )
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_issuance_multi_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Sample a new random scalars.
            let b = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let e = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let d = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let sk = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let mut vals: Vec<<$config as CurveConfig>::ScalarField> = Vec::new();
            vals.push(b);
            vals.push(e);
            vals.push(d);
            vals.push(sk);

            let gen = PedersenComm::<$config>::get_main_generator();
            let pk = gen.mul(sk).into_affine();

            // And commit to them.
            let (com, gens) = PedersenComm::<$config>::new_multi(vals.clone(), &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(b"test-issue-multi");
            let proof = IPM::create(
                &mut transcript,
                &mut OsRng,
                vals.clone(),
                &com,
                gens.clone(),
            );

            // And now just check how long it takes to verify the proof.
            c.bench_function(
                concat!($curve_name, " issuance proof multi verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(b"test-issue-multi");
                        proof.verify(&mut transcript_v, &com.comm, &pk, vals.len(), gens.clone());
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_equality_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            let label = b"PedersenEq";

            let a = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let c1 = PedersenComm::<$config>::new(a, &mut OsRng);
            let c2 = PedersenComm::<$config>::new(a, &mut OsRng);

            c.bench_function(concat!($curve_name, " equality proof prover time"), |b| {
                b.iter(|| {
                    let mut transcript = Transcript::new(label);
                    EP::create(&mut transcript, &mut OsRng, &c1, &c2);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_equality_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            let label = b"PedersenEq";

            let a = <$config as CurveConfig>::ScalarField::rand(&mut OsRng);
            let c1 = PedersenComm::<$config>::new(a, &mut OsRng);
            let c2 = PedersenComm::<$config>::new(a, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = EP::create(&mut transcript, &mut OsRng, &c1, &c2);

            c.bench_function(concat!($curve_name, " equality proof verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(&mut transcript_v, &c1.comm, &c2.comm);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_mul_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type SF = <$config as CurveConfig>::ScalarField;
            type PC = PedersenComm<$config>;

            let label = b"PedersenMul";
            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let z = a * b;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);

            c.bench_function(concat!($curve_name, " mul proof prover time"), |bf| {
                bf.iter(|| {
                    let mut transcript = Transcript::new(label);
                    MP::create(&mut transcript, &mut OsRng, &a, &b, &c1, &c2, &c3);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_mul_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type SF = <$config as CurveConfig>::ScalarField;
            type PC = PedersenComm<$config>;

            let label = b"PedersenMul";
            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let z = a * b;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);
            let mut transcript = Transcript::new(label);
            let proof = MP::create(&mut transcript, &mut OsRng, &a, &b, &c1, &c2, &c3);

            c.bench_function(concat!($curve_name, " mul proof verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(&mut transcript_v, &c1.comm, &c2.comm, &c3.comm);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_non_zero_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type SF = <$config as CurveConfig>::ScalarField;
            type PC = PedersenComm<$config>;

            let label = b"PedersenNonZero";
            let x = SF::rand(&mut OsRng);

            let c1: PC = PC::new(x, &mut OsRng);

            c.bench_function(concat!($curve_name, " non-zero proof prover time"), |bf| {
                bf.iter(|| {
                    let mut transcript = Transcript::new(label);
                    NZP::create(&mut transcript, &mut OsRng, &x, &c1);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_non_zero_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type SF = <$config as CurveConfig>::ScalarField;
            type PC = PedersenComm<$config>;

            let label = b"PedersenNonZero";
            let x = SF::rand(&mut OsRng);

            let c1: PC = PC::new(x, &mut OsRng);
            let mut transcript = Transcript::new(label);
            let proof = NZP::create(&mut transcript, &mut OsRng, &x, &c1);

            c.bench_function(concat!($curve_name, " non-zero proof verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(&mut transcript_v, &c1.comm);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_point_add_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
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

            c.bench_function(concat!($curve_name, " CDLS point add prover time"), |bf| {
                bf.iter(|| {
                    let mut transcript = Transcript::new(label);
                    EPAP::<$config>::create_with_existing_commitments(
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
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_point_add_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
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
            let proof: EPAP<Config> = EPAP::create_with_existing_commitments(
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

            let comm_size = cax.comm.compressed_size()
                + cbx.comm.compressed_size()
                + ctx.comm.compressed_size()
                + cay.comm.compressed_size()
                + cby.comm.compressed_size()
                + cty.comm.compressed_size();

            println!(
                "CDLS point add proof size for {}:{}",
                $curve_name,
                proof.serialized_size() + comm_size
            );

            c.bench_function(
                concat!($curve_name, " CDLS point add verifier time"),
                |bf| {
                    bf.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(
                            &mut transcript_v,
                            &cax.comm,
                            &cay.comm,
                            &cbx.comm,
                            &cby.comm,
                            &ctx.comm,
                            &cty.comm,
                        );
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_zk_attest_point_add_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
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
            let (cax, cay, cbx, cby, ctx, cty) =
                <$config as PedersenConfig>::create_commitments_to_coords(a, b, t, &mut OsRng);

            c.bench_function(
                concat!($curve_name, " zk attest point add prover time"),
                |bf| {
                    bf.iter(|| {
                        let mut transcript = Transcript::new(label);
                        ZKEPAP::<$config>::create_with_existing_commitments(
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
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_zk_attest_point_add_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
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
            let (cax, cay, cbx, cby, ctx, cty) =
                <$config as PedersenConfig>::create_commitments_to_coords(a, b, t, &mut OsRng);
            let mut transcript = Transcript::new(label);
            let proof: ZKEPAP<Config> = ZKEPAP::create_with_existing_commitments(
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
            let comm_size = cax.comm.compressed_size()
                + cbx.comm.compressed_size()
                + ctx.comm.compressed_size()
                + cay.comm.compressed_size()
                + cby.comm.compressed_size()
                + cty.comm.compressed_size();
            println!(
                "ZKAttest point add proof size for {}:{}",
                $curve_name,
                proof.serialized_size() + comm_size
            );

            let mut transcript_v = Transcript::new(label);
            c.bench_function(
                concat!($curve_name, " zk attest point add verifier time"),
                |bf| {
                    bf.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(
                            &mut transcript_v,
                            &cax.comm,
                            &cay.comm,
                            &cbx.comm,
                            &cby.comm,
                            &ctx.comm,
                            &cty.comm,
                        );
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_scalar_mul_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            c.bench_function(concat!($curve_name, " CDLS scalar mul prover time"), |b| {
                b.iter(|| {
                    let mut transcript = Transcript::new(label);
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
                    let chal = ECSMP::<$config>::challenge_scalar(&mut transcript);
                    ECSMP::<$config>::create_proof(
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
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_scalar_mul_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

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

            let comm_size =
                c1.compressed_size() + c2.comm.compressed_size() + c3.comm.compressed_size();
            println!(
                "CDLS scalar mul proof size for {}:{}",
                $curve_name,
                proof.serialized_size() + comm_size
            );

            c.bench_function(
                concat!($curve_name, " CDLS scalar mul verifier time"),
                |b| {
                    b.iter(|| {
                        proof.verify_proof(&OGENERATOR, &chal, &c1, &c2.comm, &c3.comm);
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_fs_scalar_mul_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenFSScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            c.bench_function(
                concat!($curve_name, " CDLS fiat-shamir scalar mul prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        FSECSMP::<$config, ECSMP<$config>>::create(
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
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_fs_scalar_mul_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenFSScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof: FSECSMP<$config, ECSMP<$config>> = FSECSMP::create(
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

            let comm_size =
                c1.compressed_size() + c2.comm.compressed_size() + c3.comm.compressed_size();
            println!(
                "CDLS fs scalar mul proof size for {}:{}",
                $curve_name,
                proof.serialized_size() + comm_size
            );

            c.bench_function(
                concat!($curve_name, " CDLS fiat-shamir scalar mul verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v, &OGENERATOR, &c1, &c2.comm, &c3.comm);
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_zk_attest_scalar_mul_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenZkAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();

            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            c.bench_function(
                concat!($curve_name, " zk attest scalar mul prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        let inter =
                            ZKECSMP::<$config>::create_intermediates_with_existing_commitments(
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
                        let chal = ZKECSMP::<$config>::challenge_scalar(&mut transcript);
                        ZKECSMP::<$config>::create_proof(
                            &s,
                            &lambda,
                            &OGENERATOR,
                            &inter,
                            &chal,
                            &c1,
                            &r1,
                            &c2,
                            &c3,
                        )
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_zk_attest_scalar_mul_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenZKAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let mut transcript = Transcript::new(label);
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

            let comm_size =
                c1.compressed_size() + c2.comm.compressed_size() + c3.comm.compressed_size();
            println!(
                "ZKAttest scalar mul proof size for {}:{}",
                $curve_name,
                proof.serialized_size()
            );

            c.bench_function(
                concat!($curve_name, " zk attest scalar mul verifier time"),
                |b| {
                    b.iter(|| {
                        proof.verify_proof(&OGENERATOR, &chal, &c1, &c2.comm, &c3.comm);
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_fs_zk_attest_scalar_mul_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenFSZkAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            c.bench_function(
                concat!($curve_name, " fiat-shamir zk attest scalar mul prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        FSECSMP::<$config, ZKECSMP<Config>>::create(
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
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_fs_zk_attest_scalar_mul_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenFSZkAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();
            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = FSECSMP::<$config, ZKECSMP<$config>>::create(
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

            let comm_size =
                c1.compressed_size() + c2.comm.compressed_size() + c3.comm.compressed_size();
            println!(
                "ZKAttest fs scalar mul proof size for {}:{}",
                $curve_name,
                proof.serialized_size()
            );

            c.bench_function(
                concat!(
                    $curve_name,
                    " fiat-shamir zk attest scalar mul verifier time"
                ),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v, &OGENERATOR, &c1, &c2.comm, &c3.comm);
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_gk_zero_one_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenGKZeroOne";
            let m = SF::ONE;
            let com: PC = PC::new(m, &mut OsRng);

            c.bench_function(concat!($curve_name, " gk zero-one prover time"), |b| {
                b.iter(|| {
                    let mut transcript = Transcript::new(label);
                    ZOP::<$config>::create(&mut transcript, &mut OsRng, &m, &com);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_gk_zero_one_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenGKZeroOne";
            let m = SF::ONE;
            let com: PC = PC::new(m, &mut OsRng);

            let mut transcript = Transcript::new(label);
            let proof = ZOP::<$config>::create(&mut transcript, &mut OsRng, &m, &com);

            c.bench_function(concat!($curve_name, " gk zero-one verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(&mut transcript_v, &com.comm);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_ecdsa_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $collective_name: tt, $collective_type: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

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

            let sign = |z: &OSF, private: &OSF| -> (OSF, OSF) {
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
            };

            let (r, s) = sign(&t, &private);

            // Now we need to make `R`.
            let u1 = t * s.inverse().unwrap();
            let u2 = r * s.inverse().unwrap();
            let R = (OGENERATOR.mul(u1) + public.mul(u2)).into_affine();

            c.bench_function(
                concat!(
                    $curve_name,
                    " ecdsa signature proof prover time ",
                    $collective_name
                ),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        ECDSASigProof::<$config, $collective_type>::create(
                            &mut transcript,
                            &mut OsRng,
                            &t,
                            &R,
                            &r,
                            &s,
                            &public,
                        );
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_ecdsa_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $collective_name: tt, $collective_type: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

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

            let sign = |z: &OSF, private: &OSF| -> (OSF, OSF) {
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
            };

            let (r, s) = sign(&t, &private);

            // Now we need to make `R`.
            let u1 = t * s.inverse().unwrap();
            let u2 = r * s.inverse().unwrap();
            let R = (OGENERATOR.mul(u1) + public.mul(u2)).into_affine();

            let mut transcript = Transcript::new(label);
            let proof = ECDSASigProof::<$config, $collective_type>::create(
                &mut transcript,
                &mut OsRng,
                &t,
                &R,
                &r,
                &s,
                &public,
            );
            c.bench_function(
                concat!(
                    $curve_name,
                    " ecdsa signature proof verifier time ",
                    $collective_name
                ),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v, &R, &t);
                    });
                },
            );
        }
    };
}

#[macro_export]
macro_rules! bench_zk_attest_fs_scalar_mul_prover_time_vary {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenZkAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();

            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            // We have to instantiate a group here for this.
            let mut group =
                c.benchmark_group(concat!($curve_name, " zk attest prover time size varying"));
            group.sample_size(10);

            // We explicitly make the size of the proof.
            for size in 0..<$config as PedersenConfig>::SECPARAM {
                let mut challenge = [0u8; 2 * 64];
                // We set the odd element bits for each piece of `size`.
                let mut tmp_size = size;
                for i in 0..2 * 64 {
                    if tmp_size == 0 {
                        break;
                    }
                    for j in [0, 2, 4, 6] {
                        if tmp_size == 0 {
                            break;
                        }
                        challenge[i] |= (1 << j);
                        tmp_size -= 1;
                    }
                }

                group.bench_with_input(format!("HW {}", size), &size, |b, &t| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        let inter = FSECSMP::<$config, ZKECSMP<Config>>::create_intermediate(
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
                        FSECSMP::<$config, ZKECSMP<Config>>::create_proof(
                            &s,
                            &lambda,
                            &OGENERATOR,
                            &inter,
                            &c1,
                            &r1,
                            &c2,
                            &c3,
                            &challenge[0..(ZKECSMP::<$config>::SHIFT_BY
                                * <$config as PedersenConfig>::SECPARAM
                                / 8)],
                        );
                    });
                });
            }

            group.finish();
        }
    };
}

#[macro_export]
macro_rules! bench_zk_attest_fs_scalar_mul_verifier_time_vary {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type PC = PedersenComm<$config>;
            type SF = <$config as CurveConfig>::ScalarField;
            type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
            const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
                <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

            let label = b"PedersenZkAttestScalarMult";
            let lambda = OSF::rand(&mut OsRng);
            let s = (OGENERATOR.mul(lambda)).into_affine();

            let (c1, r1) = <$config as PedersenConfig>::create_commit_other(&lambda, &mut OsRng);
            let c2 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.x), &mut OsRng);
            let c3 = PC::new(<$config as PedersenConfig>::from_ob_to_sf(s.y), &mut OsRng);

            // We have to instantiate a group here for this.
            let mut group = c.benchmark_group(concat!(
                $curve_name,
                " zk attest verifier time size varying"
            ));
            group.sample_size(10);

            let comm_size =
                c1.compressed_size() + c2.comm.compressed_size() + c3.comm.compressed_size();

            // We explicitly make the size of the proof.
            for size in 0..<$config as PedersenConfig>::SECPARAM {
                let mut challenge = [0u8; 64];
                // We set the odd element bits for each piece of `size`.
                let mut tmp_size = size;
                for i in 0..64 {
                    if tmp_size == 0 {
                        break;
                    }
                    for j in [0, 2, 4, 6] {
                        if tmp_size == 0 {
                            break;
                        }
                        challenge[i] |= (1 << j);
                        tmp_size -= 1;
                    }
                }

                let mut transcript = Transcript::new(label);
                let inter = FSECSMP::<$config, ZKECSMP<Config>>::create_intermediate(
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
                let proof = FSECSMP::<$config, ZKECSMP<Config>>::create_proof(
                    &s,
                    &lambda,
                    &OGENERATOR,
                    &inter,
                    &c1,
                    &r1,
                    &c2,
                    &c3,
                    &challenge[0..(ZKECSMP::<$config>::SHIFT_BY
                        * <$config as PedersenConfig>::SECPARAM
                        / 8)],
                );
                println!("HW {}, size {}", size, proof.serialized_size() + comm_size);
                group.bench_with_input(format!("HW {}", size), &size, |b, &t| {
                    b.iter(|| {
                        proof.verify_proof_with_challenge(
                            &OGENERATOR,
                            &c1,
                            &c2.comm,
                            &c3.comm,
                            &challenge[0..(ZKECSMP::<$config>::SHIFT_BY
                                * <$config as PedersenConfig>::SECPARAM
                                / 8)],
                        );
                    });
                });
            }
            group.finish();
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_import_everything {
    () => {
        use ark_ec::{
            models::CurveConfig,
            short_weierstrass::{self as sw, SWCurveConfig},
            AffineRepr, CurveGroup,
        };
        use ark_ff::fields::Field;
        use ark_serialize::CanonicalSerialize;
        use ark_std::UniformRand;
        use core::ops::Mul;
        use criterion::{black_box, criterion_group, criterion_main, Criterion};
        use merlin::Transcript;
        use pedersen::{
            ec_collective::CDLSCollective,
            ec_point_add_protocol::{ECPointAddIntermediate as EPAI, ECPointAddProof as EPAP},
            ecdsa_protocol::ECDSASigProof,
            equality_protocol::EqualityProof as EP,
            fs_scalar_mul_protocol::FSECScalarMulProof as FSECSMP,
            gk_zero_one_protocol::ZeroOneProof as ZOP,
            issuance_protocol::IssuanceProofMulti as IPM,
            mul_protocol::MulProof as MP,
            non_zero_protocol::NonZeroProof as NZP,
            opening_protocol::OpeningProof as OP,
            opening_protocol::OpeningProofMulti as OPM,
            pedersen_config::PedersenComm,
            pedersen_config::PedersenConfig,
            point_add::PointAddProtocol,
            scalar_mul::ScalarMulProtocol,
            scalar_mul_protocol::{
                ECScalarMulProof as ECSMP, ECScalarMulProofIntermediate as ECSMPI,
            },
            transcript::{ECScalarMulTranscript, ZKAttestECScalarMulTranscript},
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
        use std::time::Duration;
    };
}

#[macro_export]
macro_rules! bench_tcurve_make_all {
    ($config: ty, $curve_name: tt, $OtherProjectiveType: ty) => {
        $crate::bench_tcurve_import_everything!();
        $crate::bench_tcurve_opening_prover_time!(
            $config,
            open_proof_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_opening_verifier_time!(
            $config,
            open_proof_verification,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_opening_multi_prover_time!(
            $config,
            open_proof_multi_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_opening_multi_verifier_time!(
            $config,
            open_proof_multi_verification,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_issuance_multi_prover_time!(
            $config,
            issue_proof_multi_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_issuance_multi_verifier_time!(
            $config,
            issue_proof_multi_verification,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_equality_prover_time!(
            $config,
            equality_proof_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_equality_verifier_time!(
            $config,
            equality_proof_verification,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_mul_prover_time!(
            $config,
            mul_proof_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_mul_verifier_time!(
            $config,
            mul_proof_verification,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_non_zero_prover_time!(
            $config,
            non_zero_proof_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_non_zero_verifier_time!(
            $config,
            non_zero_proof_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_point_add_prover_time!(
            $config,
            point_add_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_point_add_verifier_time!(
            $config,
            point_add_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_zk_attest_point_add_prover_time!(
            $config,
            zk_attest_point_add_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_zk_attest_point_add_verifier_time!(
            $config,
            zk_attest_point_add_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_scalar_mul_prover_time!(
            $config,
            scalar_mul_creation,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_scalar_mul_verifier_time!(
            $config,
            scalar_mul_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_fs_scalar_mul_prover_time!(
            $config,
            fs_scalar_mul_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_fs_scalar_mul_verifier_time!(
            $config,
            fs_scalar_mul_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_zk_attest_scalar_mul_prover_time!(
            $config,
            zk_attest_scalar_mul_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_zk_attest_scalar_mul_verifier_time!(
            $config,
            zk_attest_scalar_mul_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_fs_zk_attest_scalar_mul_prover_time!(
            $config,
            fs_zk_attest_scalar_mul_creation,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tcurve_fs_zk_attest_scalar_mul_verifier_time!(
            $config,
            fs_zk_attest_scalar_mul_verification,
            $curve_name,
            $OtherProjectiveType
        );

        $crate::bench_tcurve_ecdsa_prover_time!(
            $config,
            ecdsa_scalar_mul_creation_cdls,
            $curve_name,
            " cdls",
            CDLSCollective
        );
        $crate::bench_tcurve_ecdsa_prover_time!(
            $config,
            ecdsa_scalar_mul_creation_zk,
            $curve_name,
            " zkattest",
            ZKAttestCollective
        );
        $crate::bench_tcurve_ecdsa_verifier_time!(
            $config,
            ecdsa_scalar_mul_verification_cdls,
            $curve_name,
            " cdls",
            CDLSCollective
        );
        $crate::bench_tcurve_ecdsa_verifier_time!(
            $config,
            ecdsa_scalar_mul_verification_zk,
            $curve_name,
            " zkattest",
            ZKAttestCollective
        );

        $crate::bench_tcurve_gk_zero_one_prover_time!($config, gk_zero_one_creation, $curve_name);
        $crate::bench_tcurve_gk_zero_one_verifier_time!(
            $config,
            gk_zero_one_verification,
            $curve_name
        );

        $crate::bench_zk_attest_fs_scalar_mul_prover_time_vary!(
            $config,
            fs_zk_attest_prover_time_v,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_zk_attest_fs_scalar_mul_verifier_time_vary!(
            $config,
            fs_zk_attest_verifier_time_v,
            $curve_name,
            $OtherProjectiveType
        );

        criterion_group!(
            benches,
            //fs_zk_attest_prover_time_v,
            //fs_zk_attest_verifier_time_v,
            open_proof_creation,
            open_proof_verification,
            open_proof_multi_creation,
            open_proof_multi_verification,
            issue_proof_multi_creation,
            issue_proof_multi_verification,
            //equality_proof_creation,
            //equality_proof_verification,
            //mul_proof_creation,
            //mul_proof_verification,
            //non_zero_proof_creation,
            //non_zero_proof_verification,
            //point_add_creation,
            //zk_attest_point_add_creation,
            //point_add_verification,
            //zk_attest_point_add_verification,
            //scalar_mul_creation,
            //zk_attest_scalar_mul_creation,
            //scalar_mul_verification,
            //zk_attest_scalar_mul_verification,
            //fs_scalar_mul_creation,
            //fs_zk_attest_scalar_mul_creation,
            //fs_scalar_mul_verification,
            //fs_zk_attest_scalar_mul_verification,
            //ecdsa_scalar_mul_creation_cdls,
            //ecdsa_scalar_mul_creation_zk,
            //ecdsa_scalar_mul_verification_cdls,
            //ecdsa_scalar_mul_verification_zk,
            //gk_zero_one_creation,
            //gk_zero_one_verification,
        );
        criterion_main!(benches);
    };
}
