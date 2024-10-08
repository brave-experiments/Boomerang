#[macro_export]
#[doc(hidden)]

macro_rules! __test_boomerang {
    ($aclconfig: ty, $config: ty, $boomerangconfig: ty, $OtherProjectiveType: ty) => {
        type CBKP = UKeyPair<$boomerangconfig>;
        type SBKP = ServerKeyPair<$boomerangconfig>;
        type IBCM = IssuanceStateC<$boomerangconfig>;
        type IBSM = IssuanceStateS<$boomerangconfig>;
        type CBCM = CollectionStateC<$boomerangconfig>;
        type CBSM = CollectionStateS<$boomerangconfig>;
        type SVBC = SpendVerifyStateC<$boomerangconfig>;
        type SVBS = SpendVerifyStateS<$boomerangconfig>;
        type ACLKP = KeyPair<$aclconfig>;
        type ACLSC = SigComm<$aclconfig>;
        type ACLCH = SigChall<$aclconfig>;
        type ACLSR = SigResp<$aclconfig>;
        type ACLSG = SigSign<$aclconfig>;
        type ACLSV = SigVerify<$aclconfig>;
        type ACLSP = SigProof<$aclconfig>;
        type ACLSPV = SigVerifProof<$aclconfig>;
        type ACLSubVals = SubVals<$aclconfig>;
        type PC = PedersenComm<$config>;
        type SF = <$config as CurveConfig>::ScalarField;
        type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
        type OSA = sw::Affine<<$config as PedersenConfig>::OCurve>;
        type AT = sw::Affine<$config>;

        const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
            <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

        #[test]
        fn test_boomerang_issuance_m1() {
            // Test the first message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());
        }

        #[test]
        fn test_boomerang_issuance_m2() {
            // Test the second message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());
        }

        #[test]
        fn test_boomerang_issuance_m3() {
            // Test the third message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);
        }

        #[test]
        fn test_boomerang_issuance_m4() {
            // Test the fourth message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);
        }

        #[test]
        fn test_boomerang_issuance_full() {
            // Test the full boomerang issuance scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);

            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);
        }

        #[test]
        fn test_boomerang_collection_round_m1() {
            // Test the first boomerang collection scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);
            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());
        }

        #[test]
        fn test_boomerang_collection_round_m2() {
            // Test the first boomerang collection scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);

            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 =
                CBSM::generate_collection_m3(&mut OsRng, &collection_m2, &mut s_col_state, &skp, v);

            assert!(collection_m3.comm.comm.is_on_curve());
        }

        #[test]
        fn test_boomerang_collection_round_m4() {
            // Test the first boomerang collection scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);
            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 =
                CBSM::generate_collection_m3(&mut OsRng, &collection_m2, &mut s_col_state, &skp, v);

            assert!(collection_m3.comm.comm.is_on_curve());

            let collection_m4 =
                CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &collection_m3);

            let collection_m5 =
                CBSM::generate_collection_m5(&collection_m4, &mut s_col_state, &skp);

            let collection_state =
                CBCM::populate_state(&mut c_col_state, &collection_m5, &skp, ckp.clone());

            assert!(collection_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(collection_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig_n = &collection_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_n,
                "message",
            );
            assert!(check == true);
        }

        #[test]
        fn test_boomerang_accumulate() {
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);

            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 =
                CBSM::generate_collection_m3(&mut OsRng, &collection_m2, &mut s_col_state, &skp, v);

            assert!(collection_m3.comm.comm.is_on_curve());

            let collection_m4 =
                CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &collection_m3);

            let collection_m5 =
                CBSM::generate_collection_m5(&collection_m4, &mut s_col_state, &skp);

            let collection_state =
                CBCM::populate_state(&mut c_col_state, &collection_m5, &skp, ckp.clone());

            let sig_n = &collection_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_n,
                "message",
            );
            assert!(check == true);

            let mut s_col_state_2 = CBSM::default();
            let collection_m1_2 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state_2);

            let mut c_col_state_2 = CBCM::default();
            let collection_m2_2 = CBCM::generate_collection_m2(
                &mut OsRng,
                collection_state,
                &collection_m1_2,
                &mut c_col_state_2,
                &skp,
            );

            assert!(collection_m2_2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3_2 = CBSM::generate_collection_m3(
                &mut OsRng,
                &collection_m2_2,
                &mut s_col_state_2,
                &skp,
                v,
            );

            assert!(collection_m3_2.comm.comm.is_on_curve());

            let collection_m4_2 =
                CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state_2, &collection_m3_2);

            let collection_m5_2 =
                CBSM::generate_collection_m5(&collection_m4_2, &mut s_col_state_2, &skp);

            let collection_state_2 =
                CBCM::populate_state(&mut c_col_state_2, &collection_m5_2, &skp, ckp.clone());

            assert!(collection_state_2.sig_state[0].sigma.zeta.is_on_curve());
            assert!(collection_state_2.sig_state[0].sigma.zeta1.is_on_curve());

            let sig_n_2 = &collection_state_2.sig_state[0];

            let check_2 = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_n_2,
                "message",
            );
            assert!(check_2 == true);
        }

        #[test]
        fn test_boomerang_spend_verify_round_m1() {
            // Test the full boomerang issuance scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);
            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 =
                CBSM::generate_collection_m3(&mut OsRng, &collection_m2, &mut s_col_state, &skp, v);

            assert!(collection_m3.comm.comm.is_on_curve());

            let collection_m4 =
                CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &collection_m3);

            let collection_m5 =
                CBSM::generate_collection_m5(&collection_m4, &mut s_col_state, &skp);

            let collection_state =
                CBCM::populate_state(&mut c_col_state, &collection_m5, &skp, ckp.clone());

            assert!(collection_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(collection_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig_n = &collection_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_n,
                "message",
            );
            assert!(check == true);

            // Start Spend/Verify protocol
            let mut s_spend_state = SVBS::default();
            let spendverify_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);

            let spend_state: Vec<SF> = vec![SF::one()];
            let mut c_spend_state = SVBC::default();
            let spendverify_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                collection_state,
                &mut c_spend_state,
                &spendverify_m1,
                &skp,
                spend_state,
            );
            assert!(spendverify_m2.comm.comm.is_on_curve());
        }

        #[test]
        fn test_boomerang_spend_verify_round_m2() {
            // Test the full boomerang issuance scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);

            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 =
                CBSM::generate_collection_m3(&mut OsRng, &collection_m2, &mut s_col_state, &skp, v);

            assert!(collection_m3.comm.comm.is_on_curve());

            let collection_m4 =
                CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &collection_m3);

            let collection_m5 =
                CBSM::generate_collection_m5(&collection_m4, &mut s_col_state, &skp);

            let collection_state =
                CBCM::populate_state(&mut c_col_state, &collection_m5, &skp, ckp.clone());

            assert!(collection_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(collection_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig_n = &collection_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_n,
                "message",
            );
            assert!(check == true);

            // Start Spend/Verify protocol
            let mut s_spend_state = SVBS::default();
            let spendverify_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);

            let spend_state: Vec<SF> = vec![SF::one()];
            let mut c_spend_state = SVBC::default();
            let spendverify_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                collection_state,
                &mut c_spend_state,
                &spendverify_m1,
                &skp,
                spend_state,
            );
            assert!(spendverify_m2.comm.comm.is_on_curve());

            // Create reward proof - server side
            let policy_state: Vec<SF> = vec![SF::from(2)];
            let spendverify_m3 = SVBS::generate_spendverify_m3(
                &mut OsRng,
                &spendverify_m2,
                &mut s_spend_state,
                &skp,
                policy_state.clone(),
            );
            assert!(spendverify_m3.comm.comm.is_on_curve());

            let spendverify_m4 =
                SVBC::generate_spendverify_m4(&mut OsRng, &mut c_spend_state, &spendverify_m3);
        }

        #[test]
        fn test_boomerang_spend_verify_round_m3() {
            // Test the full boomerang issuance scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let mut state = IBCM::default();
            let issuance_m1 = IBCM::generate_issuance_m1(&ckp, &mut state, &mut OsRng);
            assert!(issuance_m1.u_pk.is_on_curve());

            let mut s_state = IBSM::default();
            let issuance_m2 =
                IBSM::generate_issuance_m2(&issuance_m1, &skp, &mut s_state, &mut OsRng);
            assert!(issuance_m2.verifying_key.is_on_curve());
            assert!(issuance_m2.tag_key.is_on_curve());

            let issuance_m3 = IBCM::generate_issuance_m3(&issuance_m2, &mut state, &mut OsRng);

            let issuance_m4 = IBSM::generate_issuance_m4(&issuance_m3, &mut s_state, &skp);

            let issuance_state = IBCM::populate_state(&issuance_m4, &mut state, &skp, ckp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig,
                "message",
            );
            assert!(check == true);

            let mut s_col_state = CBSM::default();
            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng, &mut s_col_state);

            let mut c_col_state = CBCM::default();
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                &collection_m1,
                &mut c_col_state,
                &skp,
            );

            assert!(collection_m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 =
                CBSM::generate_collection_m3(&mut OsRng, &collection_m2, &mut s_col_state, &skp, v);

            assert!(collection_m3.comm.comm.is_on_curve());

            let collection_m4 =
                CBCM::generate_collection_m4(&mut OsRng, &mut c_col_state, &collection_m3);

            let collection_m5 =
                CBSM::generate_collection_m5(&collection_m4, &mut s_col_state, &skp);

            let collection_state =
                CBCM::populate_state(&mut c_col_state, &collection_m5, &skp, ckp.clone());

            assert!(collection_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(collection_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig_n = &collection_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_n,
                "message",
            );
            assert!(check == true);

            // Start Spend/Verify protocol
            let mut s_spend_state = SVBS::default();
            let spendverify_m1 = SVBS::generate_spendverify_m1(&mut OsRng, &mut s_spend_state);

            let spend_state: Vec<SF> = vec![SF::one()];
            let mut c_spend_state = SVBC::default();
            let spendverify_m2 = SVBC::generate_spendverify_m2(
                &mut OsRng,
                collection_state,
                &mut c_spend_state,
                &spendverify_m1,
                &skp,
                spend_state,
            );
            assert!(spendverify_m2.comm.comm.is_on_curve());

            // Create reward proof - server side
            let policy_state: Vec<SF> = vec![SF::from(2)];
            let spendverify_m3 = SVBS::generate_spendverify_m3(
                &mut OsRng,
                &spendverify_m2,
                &mut s_spend_state,
                &skp,
                policy_state.clone(),
            );
            assert!(spendverify_m3.comm.comm.is_on_curve());

            let spendverify_m4 =
                SVBC::generate_spendverify_m4(&mut OsRng, &mut c_spend_state, &spendverify_m3);

            let spendverify_m5 =
                SVBS::generate_spendverify_m5(&spendverify_m4, &mut s_spend_state, &skp);

            let spendverify_state =
                SVBC::populate_state(&mut c_spend_state, &spendverify_m5, &skp, ckp.clone());
            assert!(spendverify_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(spendverify_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig_s = &spendverify_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                &sig_s,
                "message",
            );
            assert!(check == true);
        }
    };
}

#[macro_export]
macro_rules! test_boomerang {
    ($mod_name: ident; $aclconfig: ty, $config: ty, $boomerangconfig: ty, $OtherProjectiveType: ty) => {
        mod $mod_name {
            use super::*;
            use ::acl::{
                config::ACLConfig, config::KeyPair, sign::SigChall, sign::SigProof, sign::SigSign,
                sign::SubVals, verify::SigComm, verify::SigResp, verify::SigVerifProof,
                verify::SigVerify,
            };
            use ::boomerang::{
                client::CollectionStateC, client::IssuanceStateC, client::SpendVerifyStateC,
                client::UKeyPair, config::BoomerangConfig, server::CollectionStateS,
                server::IssuanceStateS, server::ServerKeyPair, server::SpendVerifyStateS,
            };
            use ark_ec::{
                models::CurveConfig,
                short_weierstrass::{self as sw, SWCurveConfig},
                AffineRepr, CurveGroup,
            };
            use ark_ff::{Field, PrimeField};
            use ark_serialize::CanonicalSerialize;
            use ark_std::One;
            use ark_std::UniformRand;
            use ark_std::Zero;
            use core::ops::Mul;
            use merlin::Transcript;
            use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig};
            use rand_core::OsRng;
            use sha2::{Digest, Sha512};
            $crate::__test_boomerang!($aclconfig, $config, $boomerangconfig, $OtherProjectiveType);
        }
    };
}
