#[macro_export]
#[doc(hidden)]

macro_rules! __test_acl {
    ($aclconfig: ty, $config: ty, $OtherProjectiveType: ty) => {
        type ACLKP = KeyPair<$aclconfig>;
        type ACLSC = SigComm<$aclconfig>;
        type ACLCH = SigChall<$aclconfig>;
        type ACLSR = SigResp<$aclconfig>;
        type ACLSG = SigSign<$aclconfig>;
        type ACLSV = SigVerify<$aclconfig>;
        type ACLSP = SigProof<$aclconfig>;
        type PC = PedersenComm<$config>;
        type SF = <$config as CurveConfig>::ScalarField;
        type OSF = <<$config as PedersenConfig>::OCurve as CurveConfig>::ScalarField;
        type OSA = sw::Affine<<$config as PedersenConfig>::OCurve>;
        type AT = sw::Affine<$config>;

        const OGENERATOR: sw::Affine<<$config as PedersenConfig>::OCurve> =
            <<$config as PedersenConfig>::OCurve as SWCurveConfig>::GENERATOR;

        #[test]
        fn test_sign_m1() {
            // Test that creating multi commitments goes through.
            let label = b"ACLSignM1";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(vals.clone(), &mut OsRng);
            let mut transcript = Transcript::new(label);

            // Test that committing to a random points works.
            assert!(c1.comm.is_on_curve());

            // Test the first message of the signature scheme.
            let kp = ACLKP::generate(&mut OsRng);
            assert!(kp.verifying_key.is_on_curve());

            let m1 = ACLSC::commit(kp, &mut OsRng, c1.comm);
            assert!(m1.a.is_on_curve());
            assert!(m1.a1.is_on_curve());
            assert!(m1.a2.is_on_curve());
        }

        #[test]
        fn test_sign_m2() {
            // Test that creating multi commitments goes through.
            let label = b"ACLSignM2";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(vals.clone(), &mut OsRng);
            let mut transcript = Transcript::new(label);

            // Test that committing to a random point works.
            assert!(c1.comm.is_on_curve());

            let kp = ACLKP::generate(&mut OsRng);
            assert!(kp.verifying_key.is_on_curve());

            let m1 = ACLSC::commit(kp.clone(), &mut OsRng, c1.comm);
            assert!(m1.a.is_on_curve());
            assert!(m1.a1.is_on_curve());
            assert!(m1.a2.is_on_curve());

            // Test the second message of the signature scheme.
            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");
        }

        #[test]
        fn test_sign_m3() {
            // Test that creating multi commitments goes through.
            let label = b"ACLSignM3";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(vals.clone(), &mut OsRng);
            let mut transcript = Transcript::new(label);

            // Test that committing to a random point works.
            assert!(c1.comm.is_on_curve());

            let kp = ACLKP::generate(&mut OsRng);
            assert!(kp.verifying_key.is_on_curve());

            let m1 = ACLSC::commit(kp.clone(), &mut OsRng, c1.comm);
            assert!(m1.a.is_on_curve());
            assert!(m1.a1.is_on_curve());
            assert!(m1.a2.is_on_curve());

            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");

            // Test the third message of the signature scheme.
            let m3 = ACLSR::respond(kp.clone(), m1.clone(), m2);
        }

        #[test]
        fn test_sign_m4() {
            // Test that creating multi commitments goes through.
            let label = b"ACLSignM4";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(vals.clone(), &mut OsRng);
            let mut transcript = Transcript::new(label);

            // Test that committing to a random point works.
            assert!(c1.comm.is_on_curve());

            let kp = ACLKP::generate(&mut OsRng);
            assert!(kp.verifying_key.is_on_curve());

            let m1 = ACLSC::commit(kp.clone(), &mut OsRng, c1.comm);
            assert!(m1.a.is_on_curve());
            assert!(m1.a1.is_on_curve());
            assert!(m1.a2.is_on_curve());

            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");

            let m3 = ACLSR::respond(kp.clone(), m1.clone(), m2);

            let m4 = ACLSG::sign(kp.verifying_key, kp.tag_key, m2.clone(), m3, "message");
            assert!(m4.sigma.zeta.is_on_curve());
            assert!(m4.sigma.zeta1.is_on_curve());
        }

        #[test]
        fn test_sign_complete() {
            // Test that creating multi commitments goes through.
            let label = b"ACLSignM5";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(vals.clone(), &mut OsRng);
            let mut transcript = Transcript::new(label);

            // Test that committing to a random point works.
            assert!(c1.comm.is_on_curve());

            let kp = ACLKP::generate(&mut OsRng);
            assert!(kp.verifying_key.is_on_curve());

            let m1 = ACLSC::commit(kp.clone(), &mut OsRng, c1.comm);
            assert!(m1.a.is_on_curve());
            assert!(m1.a1.is_on_curve());
            assert!(m1.a2.is_on_curve());

            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");

            let m3 = ACLSR::respond(kp.clone(), m1.clone(), m2);

            let m4 = ACLSG::sign(kp.verifying_key, kp.tag_key, m2.clone(), m3, "message");
            assert!(m4.sigma.zeta.is_on_curve());
            assert!(m4.sigma.zeta1.is_on_curve());

            let check = ACLSV::verify(kp.verifying_key, kp.tag_key, m4.clone(), "message");
            assert!(check == true);
        }

        #[test]
        fn test_sign_proof() {
            // Test that creating multi commitments goes through.
            let label = b"ACLSignM6";

            let b = SF::rand(&mut OsRng);
            let c = SF::rand(&mut OsRng);
            let d = SF::rand(&mut OsRng);
            let mut vals: Vec<SF> = Vec::new();
            vals.push(b);
            vals.push(c);
            vals.push(d);

            let (c1, gens) = PC::new_multi(vals.clone(), &mut OsRng);
            let mut transcript = Transcript::new(label);

            // Test that committing to a random point works.
            assert!(c1.comm.is_on_curve());

            let kp = ACLKP::generate(&mut OsRng);
            assert!(kp.verifying_key.is_on_curve());

            let m1 = ACLSC::commit(kp.clone(), &mut OsRng, c1.comm);
            assert!(m1.a.is_on_curve());
            assert!(m1.a1.is_on_curve());
            assert!(m1.a2.is_on_curve());

            let m2 = ACLCH::challenge(kp.tag_key, kp.verifying_key, &mut OsRng, m1, "message");

            let m3 = ACLSR::respond(kp.clone(), m1.clone(), m2);

            let m4 = ACLSG::sign(kp.verifying_key, kp.tag_key, m2.clone(), m3, "message");
            assert!(m4.sigma.zeta.is_on_curve());
            assert!(m4.sigma.zeta1.is_on_curve());

            let check = ACLSV::verify(kp.verifying_key, kp.tag_key, m4.clone(), "message");
            assert!(check == true);

            let proof = ACLSP::prove(
                &mut OsRng,
                kp.tag_key,
                m4.clone(),
                vals,
                gens.generators,
                c1.r,
            );

            assert!(proof.b_gamma.is_on_curve());
            assert!(proof.pi1.t1.is_on_curve());
            assert!(proof.pi1.t2.is_on_curve());
            assert!(proof.pi2.t3.is_on_curve());
        }
    };
}

#[macro_export]
macro_rules! test_acl {
    ($mod_name: ident; $aclconfig: ty, $config: ty, $OtherProjectiveType: ty) => {
        mod $mod_name {
            use super::*;
            use acl::{
                config::ACLConfig, config::KeyPair, sign::SigChall, sign::SigProof, sign::SigSign,
                verify::SigComm, verify::SigResp, verify::SigVerify,
            };
            use ark_ec::{
                models::CurveConfig,
                short_weierstrass::{self as sw, SWCurveConfig},
                AffineRepr, CurveGroup,
            };
            use ark_ff::{Field, PrimeField};
            use ark_serialize::CanonicalSerialize;
            use ark_std::UniformRand;
            use ark_std::Zero;
            use core::ops::Mul;
            use merlin::Transcript;
            use pedersen::{
                ec_collective::CDLSCollective,
                ec_point_add_protocol::{ECPointAddIntermediate as EPAI, ECPointAddProof as EPAP},
                ecdsa_protocol::ECDSASigProof,
                equality_protocol::EqualityProof as EP,
                fs_scalar_mul_protocol::FSECScalarMulProof as FSECMP,
                gk_zero_one_protocol::{ZeroOneProof as ZOP, ZeroOneProofIntermediate as ZOPI},
                interpolate::PolynomialInterpolation,
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
            $crate::__test_acl!($aclconfig, $config, $OtherProjectiveType);
        }
    };
}
