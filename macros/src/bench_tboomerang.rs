#[macro_export]
macro_rules! bench_tboomerang_issuance_m1_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m1 time"), |b| {
                b.iter(|| {
                    IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m2_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m2 time"), |b| {
                b.iter(|| {
                    IBSM::generate_issuance_m2(m1.clone(), skp.clone(), &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m3_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), skp.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m3 time"), |b| {
                b.iter(|| {
                    IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m4_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), skp.clone(), &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m4 time"), |b| {
                b.iter(|| {
                    IBSM::generate_issuance_m4(m3.clone(), m2.clone(), skp.clone());
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m5_time {
    ($config: ty, $bench_name: ident, $curve_name: tt, $OtherProjectiveType: ty) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), skp.clone(), &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), skp.clone());

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m5 time"), |b| {
                b.iter(|| {
                    IBCM::populate_state(m3.clone(), m4.clone(), skp.clone(), kp.clone());
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_import_everything {
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
        use boomerang::{
            client::IssuanceC as IBCM, client::UKeyPair as CBKP, config::BoomerangConfig,
            server::IssuanceS as IBSM, server::ServerKeyPair as SBKP,
        };
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
macro_rules! bench_tboomerang_make_all {
    ($config: ty, $curve_name: tt, $OtherProjectiveType: ty) => {
        $crate::bench_tboomerang_import_everything!();
        $crate::bench_tboomerang_issuance_m1_time!(
            $config,
            boomerang_issuance_m1,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tboomerang_issuance_m2_time!(
            $config,
            boomerang_issuance_m2,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tboomerang_issuance_m3_time!(
            $config,
            boomerang_issuance_m3,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tboomerang_issuance_m4_time!(
            $config,
            boomerang_issuance_m4,
            $curve_name,
            $OtherProjectiveType
        );
        $crate::bench_tboomerang_issuance_m5_time!(
            $config,
            boomerang_issuance_m5,
            $curve_name,
            $OtherProjectiveType
        );

        criterion_group!(
            benches,
            boomerang_issuance_m1,
            boomerang_issuance_m2,
            boomerang_issuance_m3,
            boomerang_issuance_m4,
            boomerang_issuance_m5
        );
        criterion_main!(benches);
    };
}
