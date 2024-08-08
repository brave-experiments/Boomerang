#[macro_export]
#[doc(hidden)]

macro_rules! __test_boomerang {
    ($aclconfig: ty, $config: ty, $boomerangconfig: ty, $OtherProjectiveType: ty) => {
        type CBKP = UKeyPair<$boomerangconfig>;
        type SBKP = ServerKeyPair<$boomerangconfig>;
        type IBCM = IssuanceC<$boomerangconfig>;
        type IBSM = IssuanceS<$boomerangconfig>;
        type CBCM = CollectionC<$boomerangconfig>;
        type CBSM = CollectionS<$boomerangconfig>;
        type SVBCM = SpendVerifyC<$boomerangconfig>;
        type SVBSM = SpendVerifyS<$boomerangconfig>;
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
        fn test_boomerang_m1() {
            // Test the first message of the boomerang scheme.
            let kp = CBKP::generate(&mut OsRng);
            assert!(kp.public_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(kp, &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());
        }

        #[test]
        fn test_boomerang_m2() {
            // Test the second message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp, &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1, &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());
        }

        #[test]
        fn test_boomerang_m3() {
            // Test the third message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp, &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2, &mut OsRng);
        }

        #[test]
        fn test_boomerang_m4() {
            // Test the fourth message of the boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp, &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);
        }

        #[test]
        fn test_boomerang_issuance_full() {
            // Test the full boomerang issuance scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp.clone(), &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), &skp, ckp.clone());

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

            let issuance_m1 = IBCM::generate_issuance_m1(ckp.clone(), &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), &skp, ckp.clone());

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

            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng);
            let collection_m2 =
                CBCM::generate_collection_m2(&mut OsRng, issuance_state, collection_m1, &skp);

            assert!(collection_m2.m2.comm.comm.is_on_curve());
        }

        #[test]
        fn test_boomerang_collection_round_m2() {
            // Test the first boomerang collection scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp.clone(), &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), &skp, ckp.clone());

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

            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng);
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                collection_m1.clone(),
                &skp,
            );

            assert!(collection_m2.m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                collection_m2,
                collection_m1.clone(),
                &skp,
                v,
            );

            assert!(collection_m3.m3.unwrap().comm.comm.is_on_curve());
        }

        #[test]
        fn test_boomerang_collection_round_m4() {
            // Test the first boomerang collection scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp.clone(), &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), &skp, ckp.clone());

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

            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng);
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                collection_m1.clone(),
                &skp,
            );

            assert!(collection_m2.m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                collection_m2.clone(),
                collection_m1.clone(),
                &skp,
                v,
            );

            assert!(collection_m3.m3.clone().unwrap().comm.comm.is_on_curve());

            let collection_m4 = CBCM::generate_collection_m4(
                &mut OsRng,
                collection_m2.clone(),
                collection_m3.clone(),
            );

            let collection_m5 =
                CBSM::generate_collection_m5(collection_m4.clone(), collection_m3.clone(), &skp);

            let collection_state = CBCM::populate_state(
                collection_m4.clone(),
                collection_m5.clone(),
                &skp,
                ckp.clone(),
            );

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

            let issuance_m1 = IBCM::generate_issuance_m1(ckp.clone(), &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), &skp, ckp.clone());

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

            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng);
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                collection_m1.clone(),
                &skp,
            );

            assert!(collection_m2.m2.comm.comm.is_on_curve());

            let v = SF::one();
            let collection_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                collection_m2.clone(),
                collection_m1.clone(),
                &skp,
                v,
            );

            assert!(collection_m3.m3.clone().unwrap().comm.comm.is_on_curve());

            let collection_m4 = CBCM::generate_collection_m4(
                &mut OsRng,
                collection_m2.clone(),
                collection_m3.clone(),
            );

            let collection_m5 =
                CBSM::generate_collection_m5(collection_m4.clone(), collection_m3.clone(), &skp);

            let collection_state = CBCM::populate_state(
                collection_m4.clone(),
                collection_m5.clone(),
                &skp,
                ckp.clone(),
            );

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

            let collection_m1_2 = CBSM::generate_collection_m1(&mut OsRng);
            let collection_m2_2 = CBCM::generate_collection_m2(
                &mut OsRng,
                collection_state,
                collection_m1_2.clone(),
                &skp,
            );

            assert!(collection_m2_2.m2.comm.comm.is_on_curve());

            let v_2 = SF::one();
            let collection_m3_2 = CBSM::generate_collection_m3(
                &mut OsRng,
                collection_m2_2.clone(),
                collection_m1_2.clone(),
                &skp,
                v_2,
            );

            assert!(collection_m3_2.m3.clone().unwrap().comm.comm.is_on_curve());

            let collection_m4_2 = CBCM::generate_collection_m4(
                &mut OsRng,
                collection_m2_2.clone(),
                collection_m3_2.clone(),
            );

            let collection_m5_2 = CBSM::generate_collection_m5(
                collection_m4_2.clone(),
                collection_m3_2.clone(),
                &skp,
            );

            let collection_state_2 = CBCM::populate_state(
                collection_m4_2.clone(),
                collection_m5_2.clone(),
                &skp,
                ckp.clone(),
            );

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
            // Test the first boomerang collection scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp.clone(), &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), &skp, &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), &skp);

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), &skp, ckp.clone());

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

            let collection_m1 = CBSM::generate_collection_m1(&mut OsRng);
            let collection_m2 = CBCM::generate_collection_m2(
                &mut OsRng,
                issuance_state,
                collection_m1.clone(),
                &skp,
            );

            assert!(collection_m2.m2.comm.comm.is_on_curve());

            let v = SF::zero(); // FIX
            let collection_m3 = CBSM::generate_collection_m3(
                &mut OsRng,
                collection_m2.clone(),
                collection_m1.clone(),
                &skp,
                v,
            );

            assert!(collection_m3.m3.clone().unwrap().comm.comm.is_on_curve());

            let collection_m4 = CBCM::generate_collection_m4(
                &mut OsRng,
                collection_m2.clone(),
                collection_m3.clone(),
            );

            let collection_m5 =
                CBSM::generate_collection_m5(collection_m4.clone(), collection_m3.clone(), &skp);

            let collection_state = CBCM::populate_state(
                collection_m4.clone(),
                collection_m5.clone(),
                &skp,
                ckp.clone(),
            );

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
            let spendverify_m1 = SVBSM::generate_spendverify_m1(&mut OsRng);

            let spendverify_m2 = SVBCM::generate_spendverify_m2(
                &mut OsRng,
                collection_state,
                spendverify_m1.clone(),
                &skp,
            );
            assert!(spendverify_m2.m2.comm.comm.is_on_curve());

            // create policy vector
            // This policy vector defines how each incentive is rewarded.
            // For this proof of concept, we just assign a static value for
            // each incenitve.
            let policy_vector: Vec<u64> = (0..64).map(|_| 5).collect();
            let policy_vector_scalar: Vec<SF> = policy_vector
                .clone()
                .into_iter()
                .map(|u64_value| SF::from(u64_value))
                .collect();
            // This state vector defines the interactions with the incentive
            // system. For the proof of concept we simple assign a static value.
            let state_vector = vec![5u64; 64]; // TODO: we are not really spending anything here

            // Create reward proof - server side
            let spend_state: Vec<SF> = vec![SF::one()];
            let policy_state: Vec<SF> = vec![SF::from(2)];
            let spendverify_m3 = SVBSM::generate_spendverify_m3(
                &mut OsRng,
                spendverify_m2.clone(),
                spendverify_m1.clone(),
                &skp,
                spend_state,
                policy_state,
            );
            assert!(spendverify_m3.m3.clone().unwrap().comm.comm.is_on_curve());
        }
    };
}

#[macro_export]
macro_rules! test_boomerang {
    ($mod_name: ident; $aclconfig: ty, $config: ty, $boomerangconfig: ty, $OtherProjectiveType: ty) => {
        mod $mod_name {
            use super::*;
            use acl::{
                config::ACLConfig, config::KeyPair, sign::SigChall, sign::SigProof, sign::SigSign,
                sign::SubVals, verify::SigComm, verify::SigResp, verify::SigVerifProof,
                verify::SigVerify,
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
            use boomerang::{
                client::CollectionC, client::IssuanceC, client::SpendVerifyC, client::UKeyPair,
                config::BoomerangConfig, server::CollectionS, server::IssuanceS,
                server::ServerKeyPair, server::SpendVerifyS,
            };
            use core::ops::Mul;
            use merlin::Transcript;
            use pedersen::{pedersen_config::PedersenComm, pedersen_config::PedersenConfig};
            use rand_core::OsRng;
            use sha2::{Digest, Sha512};
            $crate::__test_boomerang!($aclconfig, $config, $boomerangconfig, $OtherProjectiveType);
        }
    };
}
