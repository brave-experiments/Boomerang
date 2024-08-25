#[macro_export]
macro_rules! bench_tboomerang_issuance_m1_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the first message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let mut state = IBCM::default();

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m1 time"), |b| {
                b.iter(|| {
                    IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m2_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the second message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let mut state = IBCM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let mut s_state = IBSM::default();

            c.bench_function(concat!($curve_name, " issuance m2 time"), |b| {
                b.iter(|| {
                    IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m3_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the third message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let mut state = IBCM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let mut s_state = IBSM::default();
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);

            c.bench_function(concat!($curve_name, " issuance m3 time"), |b| {
                b.iter(|| {
                    IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m4_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the fourth message of the boomerang scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let mut state = IBCM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let mut s_state = IBSM::default();
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);

            // Now we can just benchmark how long it takes for the first message.
            c.bench_function(concat!($curve_name, " issuance m4 time"), |b| {
                b.iter(|| {
                    IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_issuance_m5_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the local population of the boomerang issuance scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);

            c.bench_function(concat!($curve_name, " issuance populate state time"), |b| {
                b.iter(|| {
                    IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();

            c.bench_function(concat!($curve_name, " collection m1 time"), |b| {
                b.iter(|| {
                    CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);

            c.bench_function(concat!($curve_name, " collection m2 time"), |b| {
                b.iter(|| {
                    CBCM::generate_collection_m2(
                        &mut OsRng,
                        i_state.clone(),
                        &c_m1,
                        &mut c_col_state,
                        &skp,
                    );
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            c.bench_function(concat!($curve_name, " collection m3 time"), |b| {
                b.iter(|| {
                    CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);

            c.bench_function(concat!($curve_name, " collection m4 time"), |b| {
                b.iter(|| {
                    CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
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

            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);

            c.bench_function(concat!($curve_name, " collection m5 time"), |b| {
                b.iter(|| {
                    CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
                });
            });
        }
    };
}

#[macro_export]
macro_rules! bench_tboomerang_collection_m6_time {
    ($config: ty, $bench_name: ident, $curve_name: tt) => {
        pub fn $bench_name(c: &mut Criterion) {
            // Bench the population of the boomerang collection scheme.
            let kp = CBKP::<$config>::generate(&mut OsRng);
            let skp = SBKP::generate(&mut OsRng);
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);

            c.bench_function(concat!($curve_name, " collection state time"), |b| {
                b.iter(|| {
                    CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
            let c_state = CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
            let mut s_spend_state = SVBS::default();

            c.bench_function(concat!($curve_name, " spend-verify m1 time"), |b| {
                b.iter(|| {
                    SVBS::<$config>::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
            let c_state = CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
            let mut s_spend_state = SVBS::default();
            let mut c_spend_state = SVBC::default();
            let s_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);
            let spend_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::one()];

            c.bench_function(concat!($curve_name, " spend-verify m2 time"), |b| {
                b.iter(|| {
                    SVBC::generate_spendverify_m2(
                        &mut OsRng,
                        c_state.clone(),
                        &mut c_spend_state,
                        &s_m1,
                        &skp,
                        spend_state.clone(),
                    );
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
            let c_state = CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
            let mut s_spend_state = SVBS::default();
            let mut c_spend_state = SVBC::default();
            let s_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);
            let spend_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::one()];
            let s_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                c_state,
                &mut c_spend_state,
                &s_m1,
                &skp,
                spend_state,
            );
            let policy_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::from(2)];

            c.bench_function(concat!($curve_name, " spend-verify m3 time"), |b| {
                b.iter(|| {
                    SVBS::generate_spendverify_m3(
                        &mut OsRng,
                        &s_m2,
                        &mut s_spend_state,
                        &skp,
                        policy_state.clone(),
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
            let c_state = CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
            let mut s_spend_state = SVBS::default();
            let mut c_spend_state = SVBC::default();
            let s_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);
            let spend_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::one()];
            let s_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                c_state,
                &mut c_spend_state,
                &s_m1,
                &skp,
                spend_state,
            );
            let policy_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::from(2)];
            let s_m3 = SVBS::generate_spendverify_m3(
                &mut OsRng,
                &s_m2,
                &mut s_spend_state,
                &skp,
                policy_state.clone(),
            );

            c.bench_function(concat!($curve_name, " spend-verify m4 time"), |b| {
                b.iter(|| {
                    SVBC::generate_spendverify_m4(&mut OsRng, &mut c_spend_state, &s_m3);
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
            let c_state = CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
            let mut s_spend_state = SVBS::default();
            let mut c_spend_state = SVBC::default();
            let s_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);
            let spend_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::one()];
            let s_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                c_state,
                &mut c_spend_state,
                &s_m1,
                &skp,
                spend_state,
            );
            let policy_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::from(2)];
            let s_m3 = SVBS::generate_spendverify_m3(
                &mut OsRng,
                &s_m2,
                &mut s_spend_state,
                &skp,
                policy_state.clone(),
            );
            let s_m4 = SVBC::generate_spendverify_m4(&mut OsRng, &mut c_spend_state, &s_m3);

            c.bench_function(concat!($curve_name, " spend-verify m5 time"), |b| {
                b.iter(|| {
                    SVBS::generate_spendverify_m5(&s_m4, &mut s_spend_state, &skp);
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
            let mut state = IBCM::default();
            let mut s_state = IBSM::default();
            let m1 = IBCM::generate_issuance_m1(&kp, &mut state, &mut OsRng);
            let m2 = IBSM::generate_issuance_m2(&m1, &skp, &mut s_state, &mut OsRng);
            let m3 = IBCM::generate_issuance_m3(&m2, &mut state, &mut OsRng);
            let m4 = IBSM::generate_issuance_m4(&m3, &mut s_state, &skp);
            let i_state = IBCM::populate_state(&m4, &mut state, &skp, kp.clone());
            let mut s_col_state = CBSM::default();
            let mut c_col_state = CBCM::default();
            let c_m1 = CBSM::<$config>::generate_collection_m1(&mut OsRng, &mut s_col_state);
            let c_m2 =
                CBCM::generate_collection_m2(&mut OsRng, i_state, &c_m1, &mut c_col_state, &skp);

            let v = <$config as CurveConfig>::ScalarField::one();
            let c_m3 = CBSM::generate_collection_m3(&mut OsRng, &c_m2, &mut s_col_state, &skp, v);
            let c_m4 = CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &c_m3);
            let c_m5 = CBSM::generate_collection_m5(&c_m4, &mut s_col_state, &skp);
            let c_state = CBCM::populate_state(&mut c_col_state, &c_m5, &skp, kp.clone());
            let mut s_spend_state = SVBS::default();
            let mut c_spend_state = SVBC::default();
            let s_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);
            let spend_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::one()];
            let s_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                c_state,
                &mut c_spend_state,
                &s_m1,
                &skp,
                spend_state,
            );
            let policy_state: Vec<<$config as CurveConfig>::ScalarField> =
                vec![<$config as CurveConfig>::ScalarField::from(2)];
            let s_m3 = SVBS::generate_spendverify_m3(
                &mut OsRng,
                &s_m2,
                &mut s_spend_state,
                &skp,
                policy_state.clone(),
            );
            let s_m4 = SVBC::generate_spendverify_m4(&mut OsRng, &mut c_spend_state, &s_m3);
            let s_m5 = SVBS::generate_spendverify_m5(&s_m4, &mut s_spend_state, &skp);

            c.bench_function(
                concat!($curve_name, " spend-verify populate state time"),
                |b| {
                    b.iter(|| {
                        SVBC::populate_state(&mut c_spend_state, &s_m5, &skp, kp.clone());
                    });
                },
            );
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
            client::CollectionStateC as CBCM, client::IssuanceStateC as IBCM,
            client::SpendVerifyStateC as SVBC, client::UKeyPair as CBKP, config::BoomerangConfig,
            server::CollectionStateS as CBSM, server::IssuanceStateS as IBSM,
            server::ServerKeyPair as SBKP, server::SpendVerifyStateS as SVBS,
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
