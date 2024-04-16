//!
//! Module containing the definition of the client side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::config::BoomerangConfig;
use acl::{config::ACLConfig, sign::SigChall, sign::SigSign};
use merlin::Transcript;
use pedersen::{
    issuance_protocol::IssuanceProofMulti, pedersen_config::Generators,
    pedersen_config::PedersenComm, pedersen_config::PedersenConfig,
};

use ark_std::{ops::Mul, UniformRand, Zero};

/// Client keypair.
///
#[derive(Clone, PartialEq)]
#[must_use]
pub struct UKeyPair<B: BoomerangConfig> {
    /// Public key
    pub public_key: sw::Affine<B>,

    /// Private component x
    x: <B as CurveConfig>::ScalarField,
}

impl<B: BoomerangConfig> UKeyPair<B> {
    pub fn affine_from_bytes_tai(bytes: &[u8]) -> sw::Affine<B> {
        extern crate crypto;
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        for i in 0..=u8::max_value() {
            let mut sha = Sha3::sha3_256();
            sha.input(bytes);
            sha.input(&[i]);
            let mut buf = [0u8; 32];
            sha.result(&mut buf);
            let res = sw::Affine::<B>::from_random_bytes(&buf);
            if let Some(point) = res {
                return point;
            }
        }
        panic!()
    }

    /// Generate a new user keypair
    #[inline]
    pub fn generate<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let x = <B as CurveConfig>::ScalarField::rand(rng);

        Self {
            public_key: (<B as SWCurveConfig>::GENERATOR.mul(x)).into_affine(),
            x,
        }
    }

    /// User public key
    pub const fn public_key(&self) -> &sw::Affine<B> {
        &self.public_key
    }
}

/// IssuanceM1. This struct acts as a container for the first message of
/// the issuance protocol.
pub struct IssuanceM1<B: BoomerangConfig> {
    /// comm: the commitment value.
    pub comm: PedersenComm<B>,
    /// pi_issuance: the proof value.
    pub pi_issuance: IssuanceProofMulti<B>,
    /// user_pk: the user's public key.
    pub u_pk: sw::Affine<B>,
    /// len: the len of the committed values.
    pub len: usize,
    /// gens: the generators of the committed values.
    pub gens: Generators<B>,
}

/// IssuanceM2. This struct acts as a container for the thrid message of
/// the issuance protocol.
pub struct IssuanceM3<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// IssuanceC. This struct represents the issuance protocol for the client.
pub struct IssuanceC<B: BoomerangConfig> {
    /// m1: the first message value.
    pub m1: IssuanceM1<B>,
    /// m3: the third message value.
    pub m3: Option<<B as CurveConfig>::ScalarField>,
}

impl<B: BoomerangConfig> IssuanceC<B> {
    /// generate_issuance_m1. This function generates the first message of the Issuance Protocol.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn generate_issuance_m1<T: RngCore + CryptoRng>(
        key_pair: UKeyPair<B>,
        rng: &mut T,
    ) -> IssuanceC<B> {
        let id_0 = <B as CurveConfig>::ScalarField::rand(rng);
        let v = <B as CurveConfig>::ScalarField::zero();
        let r_0 = <B as CurveConfig>::ScalarField::rand(rng);

        let mut vals: Vec<<B as CurveConfig>::ScalarField> = Vec::new();
        vals.push(id_0);
        vals.push(v);
        vals.push(key_pair.x);
        vals.push(r_0);

        let (c1, gens) = PedersenComm::new_multi(vals.clone(), rng);

        let label = b"BoomerangM1";
        let mut transcript = Transcript::new(label);

        let proof =
            IssuanceProofMulti::create(&mut transcript, rng, vals.clone(), &c1, gens.clone());

        let m1 = IssuanceM1 {
            comm: c1,
            pi_issuance: proof,
            u_pk: key_pair.public_key,
            len: vals.len(),
            gens: gens.clone(),
        };

        Self { m1: m1, m3: None }
    }
}
