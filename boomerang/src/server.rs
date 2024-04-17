//!
//! Module containing the definition of the client side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
};
use rand::{CryptoRng, RngCore};

use crate::client::IssuanceC;
use crate::config::BoomerangConfig;

use acl::{config::KeyPair, verify::SigComm, verify::SigResp};
use merlin::Transcript;
use pedersen::pedersen_config::PedersenComm;

use ark_std::{UniformRand, Zero};

/// Server keypair.
///
#[derive(Clone)]
pub struct ServerKeyPair<B: BoomerangConfig> {
    /// Public key
    pub s_key_pair: KeyPair<B>,
}

impl<B: BoomerangConfig> ServerKeyPair<B> {
    /// Generate a new server keypair
    #[inline]
    pub fn generate<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let keys = KeyPair::generate(rng);

        Self { s_key_pair: keys }
    }

    /// Server public key
    pub const fn public_key(&self) -> &sw::Affine<B> {
        &self.s_key_pair.verifying_key
    }

    /// Server tag key
    pub const fn tag_key(&self) -> &sw::Affine<B> {
        &self.s_key_pair.tag_key
    }
}

/// IssuanceM2. This struct acts as a container for the second message of
/// the issuance protocol.
#[derive(Clone)]
pub struct IssuanceM2<B: BoomerangConfig> {
    /// comm: the commitment value.
    pub comm: PedersenComm<B>,
    /// sig_commit: the first signature value.
    pub sig_commit: SigComm<B>,
    /// Serial Number
    pub id_1: <B as CurveConfig>::ScalarField,
    /// Public key
    pub verifying_key: sw::Affine<B>,
    /// Tag public key
    pub tag_key: sw::Affine<B>,
}

/// IssuanceM4. This struct acts as a container for the fourth message of
/// the issuance protocol.
#[derive(Clone)]
pub struct IssuanceM4<B: BoomerangConfig> {
    /// s: the signature response value.
    pub s: SigResp<B>,
}

/// IssuanceS. This struct represents the issuance protocol for the server.
#[derive(Clone)]
pub struct IssuanceS<B: BoomerangConfig> {
    /// m2: the second message value.
    pub m2: IssuanceM2<B>,
    /// m4: the fourth message value.
    pub m4: Option<IssuanceM4<B>>,
}

impl<B: BoomerangConfig + pedersen::pedersen_config::PedersenConfig + acl::config::ACLConfig>
    IssuanceS<B>
{
    /// generate_issuance_m2. This function generates the second message of the Issuance Protocol.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn generate_issuance_m2<T: RngCore + CryptoRng>(
        c_m: IssuanceC<B>,
        key_pair: ServerKeyPair<B>,
        rng: &mut T,
    ) -> IssuanceS<B> {
        let label = b"BoomerangM1";
        let mut transcript = Transcript::new(label);
        let check = c_m.m1.pi_issuance.verify(
            &mut transcript,
            &c_m.m1.comm.comm,
            &c_m.m1.u_pk,
            c_m.m1.len,
            c_m.m1.gens.clone(),
        );

        if !check {
            panic!("Boomerang: invalid proof");
        }

        let id_1 = <B as CurveConfig>::ScalarField::rand(rng);

        let v1 = <B as CurveConfig>::ScalarField::zero();
        let v2 = <B as CurveConfig>::ScalarField::zero();
        let v3 = <B as CurveConfig>::ScalarField::zero();
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_1, v1, v2, v3];

        let c1 = PedersenComm::new_multi_with_all_generators(vals.clone(), rng, c_m.m1.gens);

        let c = c1 + c_m.m1.comm;

        let sig_comm = SigComm::commit(key_pair.s_key_pair.clone(), rng, c.comm);
        let m2 = IssuanceM2 {
            id_1,
            comm: c,
            sig_commit: sig_comm,
            verifying_key: key_pair.s_key_pair.verifying_key,
            tag_key: key_pair.s_key_pair.tag_key,
        };

        Self { m2, m4: None }
    }

    pub fn generate_issuance_m4(
        c_m: IssuanceC<B>,
        s_m: IssuanceS<B>,
        key_pair: ServerKeyPair<B>,
    ) -> IssuanceS<B> {
        let sig_resp = SigResp::respond(
            key_pair.s_key_pair.clone(),
            s_m.m2.sig_commit,
            c_m.m3.unwrap().e,
        );
        let m4 = IssuanceM4 { s: sig_resp };

        Self {
            m2: s_m.m2,
            m4: Some(m4),
        }
    }
}
