#[macro_export]
macro_rules! bench_tboomerang_issuance_m1_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
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
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m2 time"), |b| {
                b.iter(|| {
                    IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m3_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);

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
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m4 time"), |b| {
                b.iter(|| {
                    IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m5_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang issuance scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m5 time"), |b| {
                b.iter(|| {
                    IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m1_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " collection m1 time"), |b| {
                b.iter(|| {
                    CBSM::<$config>::generate_collection_m1(&mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m2_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the second message of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " collection m2 time"), |b| {
                b.iter(|| {
                    CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m3_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the third message of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " collection m3 time"), |b| {
                b.iter(|| {
                    CBSM::generate_collection_m3(&mut OsRng, c_m2.clone(), c_m1.clone(), &skp, v);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m4_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the fourth message of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 =
                CBSM::generate_collection_m3(&mut OsRng, c_m2.clone(), c_m1.clone(), &skp, v);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " collection m4 time"), |b| {
                b.iter(|| {
                    CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m5_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the fifth message of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 =
                CBSM::generate_collection_m3(&mut OsRng, c_m2.clone(), c_m1.clone(), &skp, v);

            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " collection m5 time"), |b| {
                b.iter(|| {
                    CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m6_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the sixth message of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 =
                CBSM::generate_collection_m3(&mut OsRng, c_m2.clone(), c_m1.clone(), &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " collection m6 time"), |b| {
                b.iter(|| {
                    CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_spending_m1_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang spending scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 =
                CBSM::generate_collection_m3(&mut OsRng, c_m2.clone(), c_m1.clone(), &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
            let c_state = CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " spending m1 time"), |b| {
                b.iter(|| {
                    SVBSM::<$config>::generate_spendverify_m1(&mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_spending_m2_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the second message of the boomerang spending scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 =
                CBSM::generate_collection_m3(&mut OsRng, c_m2.clone(), c_m1.clone(), &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
            let c_state = CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());

            let s_m1 = SVBSM::generate_spendverify_m1(&mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " spending m2 time"), |b| {
                b.iter(|| {
                    SVBCM::generate_spendverify_m2(&mut OsRng, c_state.clone(), s_m1.clone(), &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_spending_m3_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the third message of the boomerang spending scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                c_m2.clone(),
                c_m1.clone(),
                &skp,
                v.clone(),
            );
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
            let c_state = CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());

            let s_m1 = SVBSM::generate_spendverify_m1(&mut OsRng);
            let s_m2 = SVBCM::generate_spendverify_m2(&mut OsRng, c_state, s_m1.clone(), &skp);

            let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
            let state_vector = vec![5u64; 64];

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " spending m3 time"), |b| {
                b.iter(|| {
                    SVBSM::generate_spendverify_m3(
                        &mut OsRng,
                        s_m2.clone(),
                        s_m1.clone(),
                        &skp,
                        v,
                        state_vector.clone(),
                        policy_vector.clone(),
                    );
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_spending_m4_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the forth message of the boomerang spending scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                c_m2.clone(),
                c_m1.clone(),
                &skp,
                v.clone(),
            );
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
            let c_state = CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());

            let s_m1 = SVBSM::generate_spendverify_m1(&mut OsRng);
            let s_m2 = SVBCM::generate_spendverify_m2(&mut OsRng, c_state, s_m1.clone(), &skp);
            let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
            let state_vector = vec![5u64; 64];
            let s_m3 = SVBSM::generate_spendverify_m3(
                &mut OsRng,
                s_m2.clone(),
                s_m1.clone(),
                &skp,
                v,
                state_vector,
                policy_vector.clone(),
            );

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " spending m4 time"), |b| {
                b.iter(|| {
                    SVBCM::generate_spendverify_m4(
                        &mut OsRng,
                        s_m2.clone(),
                        s_m3.clone(),
                        policy_vector.clone(),
                    );
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_spending_m5_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the fifth message of the boomerang spending scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                c_m2.clone(),
                c_m1.clone(),
                &skp,
                v.clone(),
            );
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
            let c_state = CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());

            let s_m1 = SVBSM::generate_spendverify_m1(&mut OsRng);
            let s_m2 = SVBCM::generate_spendverify_m2(&mut OsRng, c_state, s_m1.clone(), &skp);
            let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
            let state_vector = vec![5u64; 64];
            let s_m3 = SVBSM::generate_spendverify_m3(
                &mut OsRng,
                s_m2.clone(),
                s_m1.clone(),
                &skp,
                v,
                state_vector,
                policy_vector.clone(),
            );
            let s_m4 = SVBCM::generate_spendverify_m4(
                &mut OsRng,
                s_m2.clone(),
                s_m3.clone(),
                policy_vector,
            );

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " spending m5 time"), |b| {
                b.iter(|| {
                    SVBSM::generate_spendverify_m5(s_m4.clone(), s_m3.clone(), &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_spending_m6_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the sixth message of the boomerang spending scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let m1 = IBCM::generate_issuance_m1(kp.clone(), &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(m1.clone(), &skp, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(m1.clone(), m2.clone(), &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(m3.clone(), m2.clone(), &skp);
            let i_state = IBCM::populate_state(m3.clone(), m4.clone(), &skp, kp.clone());
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state.clone(), c_m1.clone(), &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                c_m2.clone(),
                c_m1.clone(),
                &skp,
                v.clone(),
            );
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, c_m2.clone(), c_m3.clone());
            let c_m5 = CBSM::generate_collection_m5(c_m4.clone(), c_m3.clone(), &skp);
            let c_state = CBCM::populate_state(c_m4.clone(), c_m5.clone(), &skp, kp.clone());

            let s_m1 = SVBSM::generate_spendverify_m1(&mut OsRng);
            let s_m2 = SVBCM::generate_spendverify_m2(&mut OsRng, c_state, s_m1.clone(), &skp);
            let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
            let state_vector = vec![5u64; 64];
            let s_m3 = SVBSM::generate_spendverify_m3(
                &mut OsRng,
                s_m2.clone(),
                s_m1.clone(),
                &skp,
                v,
                state_vector,
                policy_vector.clone(),
            );
            let s_m4 = SVBCM::generate_spendverify_m4(
                &mut OsRng,
                s_m2.clone(),
                s_m3.clone(),
                policy_vector,
            );
            let s_m5 = SVBSM::generate_spendverify_m5(s_m4.clone(), s_m3.clone(), &skp);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " spending m6 time"), |b| {
                b.iter(|| {
                    SVBCM::populate_state(s_m4.clone(), s_m5.clone(), &skp, kp.clone());
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
        use ark_std::One;
        use ark_std::UniformRand;
        use boomerang::{
            client::CollectionC as CBCM, client::IssuanceC as IBCM, client::SpendVerifyC as SVBCM,
            client::UKeyPair as CBKP, config::BoomerangConfig, server::CollectionS as CBSM,
            server::IssuanceS as IBSM, server::ServerKeyPair as SBKP,
            server::SpendVerifyS as SVBSM,
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
    ($config: ty, $curve_name: tt) => {
        $crate::bench_tboomerang_import_everything!();
        $crate::bench_tboomerang_issuance_m1_time!($config, boomerang_issuance_m1, $curve_name);
        $crate::bench_tboomerang_issuance_m2_time!($config, boomerang_issuance_m2, $curve_name);
        $crate::bench_tboomerang_issuance_m3_time!($config, boomerang_issuance_m3, $curve_name);
        $crate::bench_tboomerang_issuance_m4_time!($config, boomerang_issuance_m4, $curve_name);
        $crate::bench_tboomerang_issuance_m5_time!($config, boomerang_issuance_m5, $curve_name);
        $crate::bench_tboomerang_collection_m1_time!($config, boomerang_collection_m1, $curve_name);
        $crate::bench_tboomerang_collection_m2_time!($config, boomerang_collection_m2, $curve_name);
        $crate::bench_tboomerang_collection_m3_time!($config, boomerang_collection_m3, $curve_name);
        $crate::bench_tboomerang_collection_m4_time!($config, boomerang_collection_m4, $curve_name);
        $crate::bench_tboomerang_collection_m5_time!($config, boomerang_collection_m5, $curve_name);
        $crate::bench_tboomerang_collection_m6_time!($config, boomerang_collection_m6, $curve_name);
        $crate::bench_tboomerang_spending_m1_time!($config, boomerang_spending_m1, $curve_name);
        $crate::bench_tboomerang_spending_m2_time!($config, boomerang_spending_m2, $curve_name);
        $crate::bench_tboomerang_spending_m3_time!($config, boomerang_spending_m3, $curve_name);
        $crate::bench_tboomerang_spending_m4_time!($config, boomerang_spending_m4, $curve_name);
        $crate::bench_tboomerang_spending_m5_time!($config, boomerang_spending_m5, $curve_name);
        $crate::bench_tboomerang_spending_m6_time!($config, boomerang_spending_m6, $curve_name);

        criterion_group!(
            benches,
            boomerang_issuance_m1,
            boomerang_issuance_m2,
            boomerang_issuance_m3,
            boomerang_issuance_m4,
            boomerang_issuance_m5,
            boomerang_collection_m1,
            boomerang_collection_m2,
            boomerang_collection_m3,
            boomerang_collection_m4,
            boomerang_collection_m5,
            boomerang_collection_m6,
            boomerang_spending_m1,
            boomerang_spending_m2,
            boomerang_spending_m3,
            boomerang_spending_m4,
            boomerang_spending_m5,
            boomerang_spending_m6,
        );
        criterion_main!(benches);
    };
}
