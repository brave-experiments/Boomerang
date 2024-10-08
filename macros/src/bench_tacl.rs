#[macro_export]
macro_rules! bench_tacl_commit_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);

            // Now we can just benchmark how long it takes to commit.
            c.bench_function(concat!($curve_name, " acl commit time"), |b| {
                b.iter(|| {
                    ACLSC::commit(&kp, &mut OsRng, com.comm);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_challenge_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);
            let m1 = ACLSC::commit(&kp, &mut OsRng, com.comm);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(concat!($curve_name, " acl challenge time"), |b| {
                b.iter(|| {
                    ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_respond_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);
            let m1 = ACLSC::commit(&kp, &mut OsRng, com.comm);
            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(concat!($curve_name, " acl respond time"), |b| {
                b.iter(|| {
                    ACLSR::respond(&kp, &m1, &m2);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_sign_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);
            let m1 = ACLSC::commit(&kp, &mut OsRng, com.comm);
            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");
            let m3 = ACLSR::respond(&kp, &m1, &m2);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(concat!($curve_name, " acl sign time"), |b| {
                b.iter(|| {
                    ACLSG::sign(kp.verifying_key, kp.tag_key, &m2, &m3, "message");
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_verify_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);
            let m1 = ACLSC::commit(&kp, &mut OsRng, com.comm);
            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");
            let m3 = ACLSR::respond(&kp, &m1, &m2);
            let m4 = ACLSG::sign(kp.verifying_key, kp.tag_key, &m2, &m3, "message");

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(concat!($curve_name, " acl verify time"), |b| {
                b.iter(|| {
                    ACLSV::verify(kp.verifying_key, kp.tag_key, &m4, "message");
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_sign_proof_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);
            let m1 = ACLSC::commit(&kp, &mut OsRng, com.comm);
            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");
            let m3 = ACLSR::respond(&kp, &m1, &m2);
            let m4 = ACLSG::sign(kp.verifying_key, kp.tag_key, &m2, &m3, "message");
            ACLSV::verify(kp.verifying_key, kp.tag_key, &m4, "message");

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(concat!($curve_name, " acl proof sign time"), |b| {
                b.iter(|| {
                    ACLSP::prove(&mut OsRng, kp.tag_key, &m4, &vals, &gens.generators, com.r);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_sign_verify_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
            let kp = ACLKP::generate(&mut OsRng);
            let m1 = ACLSC::commit(&kp, &mut OsRng, com.comm);
            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");
            let m3 = ACLSR::respond(&kp, &m1, &m2);
            let m4 = ACLSG::sign(kp.verifying_key, kp.tag_key, &m2, &m3, "message");
            ACLSV::verify(kp.verifying_key, kp.tag_key, &m4, "message");
            let proof = ACLSP::prove(&mut OsRng, kp.tag_key, &m4, &vals, &gens.generators, com.r);

            // Now we can just benchmark how long it takes to create a new multi proof.
            c.bench_function(concat!($curve_name, " acl proof verify time"), |b| {
                b.iter(|| ACLSPV::verify(&proof, kp.tag_key, &m4, &gens.generators));
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tacl_import_everything {
    () => {
        use acl::{
            config::ACLConfig, config::KeyPair as ACLKP, sign::SigChall as ACLCH,
            sign::SigProof as ACLSP, sign::SigSign as ACLSG, verify::SigComm as ACLSC,
            verify::SigResp as ACLSR, verify::SigVerifProof as ACLSPV, verify::SigVerify as ACLSV,
        };
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
            issuance_protocol::IssuanceProofMulti as IPM, opening_protocol::OpeningProof as OP,
            opening_protocol::OpeningProofMulti as OPM, pedersen_config::PedersenComm,
            pedersen_config::PedersenConfig,
        };
        use rand_core::OsRng;
        use sha2::{Digest, Sha512};
        use std::time::Duration;
    };
}

#[macro_export]
macro_rules! bench_tacl_make_all {
    ($config: ty, $curve_name: tt) => {
        $crate::bench_tacl_import_everything!();
        $crate::bench_tacl_commit_time!($config, acl_commit, $curve_name);
        $crate::bench_tacl_challenge_time!($config, acl_challenge, $curve_name);
        $crate::bench_tacl_respond_time!($config, acl_respond, $curve_name);
        $crate::bench_tacl_sign_time!($config, acl_sign, $curve_name);
        $crate::bench_tacl_verify_time!($config, acl_verify, $curve_name);
        $crate::bench_tacl_sign_proof_time!($config, acl_sign_proof, $curve_name);
        $crate::bench_tacl_sign_verify_time!($config, acl_sign_verify, $curve_name);

        criterion_group!(
            benches,
            acl_commit,
            acl_challenge,
            acl_respond,
            acl_sign,
            acl_verify,
            acl_sign_proof,
            acl_sign_verify,
        );
        criterion_main!(benches);
    };
}
