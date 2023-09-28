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

            c.bench_function(concat!($curve_name, " point add prover time"), |bf| {
                bf.iter(|| {
                    let mut transcript = Transcript::new(label);
                    EPAP::<$config>::create(&mut transcript, &mut OsRng, a, b, t);
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
            let mut transcript = Transcript::new(label);
            let proof: EPAP<Config> = EPAP::create(&mut transcript, &mut OsRng, a, b, t);

            c.bench_function(concat!($curve_name, " point add verifier time"), |bf| {
                bf.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(&mut transcript_v);
                });
            });
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

            c.bench_function(
                concat!($curve_name, " zk attest point add prover time"),
                |bf| {
                    bf.iter(|| {
                        let mut transcript = Transcript::new(label);
                        ZKEPAP::<$config>::create(&mut transcript, &mut OsRng, a, b, t);
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
            let mut transcript = Transcript::new(label);
            let proof: ZKEPAP<Config> = ZKEPAP::create(&mut transcript, &mut OsRng, a, b, t);

            let mut transcript_v = Transcript::new(label);
            c.bench_function(
                concat!($curve_name, " zk attest point add verifier time"),
                |bf| {
                    bf.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v);
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

            c.bench_function(concat!($curve_name, " scalar mul prover time"), |b| {
                b.iter(|| {
                    let mut transcript = Transcript::new(label);
                    ECSMP::<$config>::create(&mut transcript, &mut OsRng, &s, &lambda, &OGENERATOR);
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
            let proof: ECSMP<Config> =
                ECSMP::create(&mut transcript, &mut OsRng, &s, &lambda, &OGENERATOR);

            c.bench_function(concat!($curve_name, " scalar mul verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(&mut transcript_v, &OGENERATOR);
                });
            });
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

            c.bench_function(
                concat!($curve_name, " fiat-shamir scalar mul prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        FSECSMP::<$config>::create(
                            &mut transcript,
                            &mut OsRng,
                            &s,
                            &lambda,
                            &OGENERATOR,
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

            let mut transcript = Transcript::new(label);
            let proof: FSECSMP<$config> =
                FSECSMP::create(&mut transcript, &mut OsRng, &s, &lambda, &OGENERATOR);

            c.bench_function(
                concat!($curve_name, " fiat-shamir scalar mul verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v, &OGENERATOR);
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

            c.bench_function(
                concat!($curve_name, " zk attest scalar mul prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        ZKECSMP::<$config>::create(
                            &mut transcript,
                            &mut OsRng,
                            &s,
                            &lambda,
                            &OGENERATOR,
                        );
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

            let mut transcript = Transcript::new(label);
            let proof =
                ZKECSMP::<$config>::create(&mut transcript, &mut OsRng, &s, &lambda, &OGENERATOR);

            c.bench_function(
                concat!($curve_name, " zk attest scalar mul verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v, &OGENERATOR);
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

            c.bench_function(
                concat!($curve_name, " fiat-shamir zk attest scalar mul prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(label);
                        FSZKECSMP::<$config>::create(
                            &mut transcript,
                            &mut OsRng,
                            &s,
                            &lambda,
                            &OGENERATOR,
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

            let mut transcript = Transcript::new(label);
            let proof =
                FSZKECSMP::<$config>::create(&mut transcript, &mut OsRng, &s, &lambda, &OGENERATOR);

            c.bench_function(
                concat!(
                    $curve_name,
                    " fiat-shamir zk attest scalar mul verifier time"
                ),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(label);
                        proof.verify(&mut transcript_v, &OGENERATOR);
                    });
                },
            );
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
        use ark_std::UniformRand;
        use core::ops::Mul;
        use criterion::{black_box, criterion_group, criterion_main, Criterion};
        use merlin::Transcript;
        use pedersen::{
            cdls_point_add_protocol::{ECPointAddIntermediate as EPAI, ECPointAddProof as EPAP},
            cdls_scalar_mul_protocol::{
                ECScalarMulProof as ECSMP, ECScalarMulProofIntermediate as ECSMPI,
            },
            equality_protocol::EqualityProof as EP,
            fs_cdls_scalar_mul_protocol::FSECScalarMulProof as FSECSMP,
            fs_zk_attest_scalar_mul_protocol::FSZKAttestECScalarMulProof as FSZKECSMP,
            mul_protocol::MulProof as MP,
            opening_protocol::OpeningProof as OP,
            pedersen_config::PedersenComm,
            pedersen_config::PedersenConfig,
            zk_attest_point_add_protocol::{
                ZKAttestPointAddProof as ZKEPAP, ZKAttestPointAddProofIntermediate as ZKEPAPI,
            },
            zk_attest_scalar_mul_protocol::{
                ZKAttestECScalarMulProof as ZKECSMP,
                ZKAttestECScalarMulProofIntermediate as ZKECSMPI,
            },
        };
        use rand_core::OsRng;
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

        criterion_group!(
            benches,
            open_proof_creation,
            open_proof_verification,
            equality_proof_creation,
            equality_proof_verification,
            mul_proof_creation,
            mul_proof_verification,
            point_add_creation,
            point_add_verification,
            zk_attest_point_add_creation,
            zk_attest_point_add_verification,
            scalar_mul_creation,
            scalar_mul_verification,
            fs_scalar_mul_creation,
            fs_scalar_mul_verification,
            zk_attest_scalar_mul_creation,
            zk_attest_scalar_mul_verification,
            fs_zk_attest_scalar_mul_creation,
            fs_zk_attest_scalar_mul_verification
        );
        criterion_main!(benches);
    };
}
