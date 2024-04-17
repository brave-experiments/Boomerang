#[macro_export]
#[doc(hidden)]

macro_rules! __test_boomerang {
    ($aclconfig: ty, $config: ty, $boomerangconfig: ty, $OtherProjectiveType: ty) => {
        type CBKP = UKeyPair<$boomerangconfig>;
        type SBKP = ServerKeyPair<$boomerangconfig>;
        type IBCM = IssuanceC<$boomerangconfig>;
        type IBSM = IssuanceS<$boomerangconfig>;
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

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1, skp, &mut OsRng);
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

            let issuance_m2 = IBSM::generate_issuance_m2(issuance_m1.clone(), skp, &mut OsRng);
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

            let issuance_m2 =
                IBSM::generate_issuance_m2(issuance_m1.clone(), skp.clone(), &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), skp.clone());
        }

        #[test]
        fn test_boomerang_full() {
            // Test the full boomerang scheme.
            let ckp = CBKP::generate(&mut OsRng);
            assert!(ckp.public_key.is_on_curve());

            let skp = SBKP::generate(&mut OsRng);
            assert!(skp.s_key_pair.verifying_key.is_on_curve());
            assert!(skp.s_key_pair.tag_key.is_on_curve());

            let issuance_m1 = IBCM::generate_issuance_m1(ckp, &mut OsRng);
            assert!(issuance_m1.m1.u_pk.is_on_curve());

            let issuance_m2 =
                IBSM::generate_issuance_m2(issuance_m1.clone(), skp.clone(), &mut OsRng);
            assert!(issuance_m2.m2.verifying_key.is_on_curve());
            assert!(issuance_m2.m2.tag_key.is_on_curve());

            let issuance_m3 =
                IBCM::generate_issuance_m3(issuance_m1.clone(), issuance_m2.clone(), &mut OsRng);

            let issuance_m4 =
                IBSM::generate_issuance_m4(issuance_m3.clone(), issuance_m2.clone(), skp.clone());

            let issuance_state =
                IBCM::populate_state(issuance_m3.clone(), issuance_m4.clone(), skp.clone());

            assert!(issuance_state.sig_state[0].sigma.zeta.is_on_curve());
            assert!(issuance_state.sig_state[0].sigma.zeta1.is_on_curve());

            let sig = &issuance_state.sig_state[0];

            let check = ACLSV::verify(
                skp.s_key_pair.verifying_key,
                skp.s_key_pair.tag_key,
                sig.clone(),
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
            use ark_std::UniformRand;
            use boomerang::{
                client::IssuanceC, client::UKeyPair, config::BoomerangConfig, server::IssuanceS,
                server::ServerKeyPair,
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
