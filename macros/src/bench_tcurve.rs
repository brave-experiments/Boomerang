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
            let (com, gens) = PedersenComm::<$config>::new_multi(&vals, &mut OsRng);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(
                concat!($curve_name, " opening multi proof prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(b"test-open-multi");
                        OPM::create(&mut transcript, &mut OsRng, &vals, &com, &gens)
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
            let (com, gens) = PedersenComm::<$config>::new_multi(&vals, &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(b"test-open-multi");
            let proof = OPM::create(&mut transcript, &mut OsRng, &vals, &com, &gens);

            // And now just check how long it takes to verify the proof.
            c.bench_function(
                concat!($curve_name, " opening proof multi verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(b"test-open-multi");
                        proof.verify(&mut transcript_v, &com.comm, vals.len(), &gens);
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
            let (com, gens) = PedersenComm::<$config>::new_multi(&vals, &mut OsRng);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(
                concat!($curve_name, " issuance multi proof prover time"),
                |b| {
                    b.iter(|| {
                        let mut transcript = Transcript::new(b"test-issue-multi");
                        IPM::create(&mut transcript, &mut OsRng, &vals, &com, &gens)
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
            let (com, gens) = PedersenComm::<$config>::new_multi(&vals, &mut OsRng);

            // Make the proof object.
            let mut transcript = Transcript::new(b"test-issue-multi");
            let proof = IPM::create(&mut transcript, &mut OsRng, &vals, &com, &gens);

            // And now just check how long it takes to verify the proof.
            c.bench_function(
                concat!($curve_name, " issuance proof multi verifier time"),
                |b| {
                    b.iter(|| {
                        let mut transcript_v = Transcript::new(b"test-issue-multi");
                        proof.verify(&mut transcript_v, &com.comm, &pk, vals.len(), &gens);
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
macro_rules! bench_tcurve_add_mul_prover_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type SF = <$config as CurveConfig>::ScalarField;
            type PC = PedersenComm<$config>;

            let label = b"PedersenMul";
            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let w = a * b;
            let t = w + c;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);
            let c4: PC = PC::new(w, &mut OsRng);
            let c5: PC = c4 + c3;

            c.bench_function(concat!($curve_name, " add-mul proof prover time"), |bf| {
                bf.iter(|| {
                    let mut transcript = Transcript::new(label);
                    AMP::create(
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
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tcurve_add_mul_verifier_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            type SF = <$config as CurveConfig>::ScalarField;
            type PC = PedersenComm<$config>;

            let label = b"PedersenMul";
            let a = SF::rand(&mut OsRng);
            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let w = a * b;
            let t = w + c;

            let c1: PC = PC::new(a, &mut OsRng);
            let c2: PC = PC::new(b, &mut OsRng);
            let c3: PC = PC::new(z, &mut OsRng);
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

            c.bench_function(concat!($curve_name, " add-mul proof verifier time"), |b| {
                b.iter(|| {
                    let mut transcript_v = Transcript::new(label);
                    proof.verify(
                        &mut transcript_v,
                        &c1.comm,
                        &c2.comm,
                        &c3.comm,
                        &c4.comm,
                        &c5.comm,
                    );
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
            add_mul_protocol::AddMulProof as AMP, equality_protocol::EqualityProof as EP,
            issuance_protocol::IssuanceProofMulti as IPM, mul_protocol::MulProof as MP,
            non_zero_protocol::NonZeroProof as NZP, opening_protocol::OpeningProof as OP,
            opening_protocol::OpeningProofMulti as OPM, pedersen_config::PedersenComm,
            pedersen_config::PedersenConfig,
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

        criterion_group!(
            benches,
            open_proof_creation,
            open_proof_verification,
            open_proof_multi_creation,
            open_proof_multi_verification,
            issue_proof_multi_creation,
            issue_proof_multi_verification,
            equality_proof_creation,
            equality_proof_verification,
            mul_proof_creation,
            mul_proof_verification,
        );
        criterion_main!(benches);
    };
}
