//!
//! Module containing the definition of the client side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    CurveGroup,
};
use rand::{CryptoRng, RngCore};

use crate::config::{BoomerangConfig, State};
use crate::server::{IssuanceS, ServerKeyPair};

use acl::{sign::SigChall, sign::SigSign};
use merlin::Transcript;
use pedersen::{
    issuance_protocol::IssuanceProofMulti, pedersen_config::Generators,
    pedersen_config::PedersenComm,
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
#[derive(Clone)]
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
    /// Serial Number
    id_0: <B as CurveConfig>::ScalarField,
}

/// IssuanceM3. This struct acts as a container for the thrid message of
/// the issuance protocol.
#[derive(Clone)]
pub struct IssuanceM3<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// IssuanceC. This struct represents the issuance protocol for the client.
#[derive(Clone)]
pub struct IssuanceC<B: BoomerangConfig> {
    /// m1: the first message value.
    pub m1: IssuanceM1<B>,
    /// m3: the third message value.
    pub m3: Option<IssuanceM3<B>>,
    /// c: the commit value.
    c: Option<PedersenComm<B>>,
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
            id_0,
        };

        Self {
            m1: m1,
            m3: None,
            c: None,
        }
    }

    pub fn generate_issuance_m3<T: RngCore + CryptoRng>(
        c_m: IssuanceC<B>,
        s_m: IssuanceS<B>,
        rng: &mut T,
    ) -> IssuanceC<B> {
        // TODO: in order to populate later
        let c = s_m.m2.comm + c_m.m1.comm;
        let id = s_m.m2.id_1 + c_m.m1.id_0;

        let sig_chall = SigChall::challenge(
            s_m.m2.tag_key,
            s_m.m2.verifying_key,
            rng,
            s_m.m2.sig_commit,
            "message",
        );

        let m3 = IssuanceM3 { e: sig_chall };

        Self {
            m1: c_m.m1,
            m3: Some(m3),
            c: Some(c),
        }
    }

    pub fn populate_state(
        c_m: IssuanceC<B>,
        s_m: IssuanceS<B>,
        key_pair: ServerKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            key_pair.s_key_pair.verifying_key.clone(),
            key_pair.s_key_pair.tag_key.clone(),
            c_m.m3.unwrap().e,
            s_m.m4.unwrap().s,
            "message",
        );

        let mut commits: Vec<PedersenComm<B>> = Vec::new();
        commits.push(c_m.c.unwrap());

        let mut sigs: Vec<SigSign<B>> = Vec::new();
        sigs.push(sig);

        let state = State {
            comm_state: commits,
            sig_state: sigs,
        };

        state
    }
}
