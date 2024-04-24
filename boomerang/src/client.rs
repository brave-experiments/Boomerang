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
use crate::server::{CollectionS, IssuanceS, ServerKeyPair};

use acl::{sign::SigChall, sign::SigProof, sign::SigSign, sign::Signature};
use merlin::Transcript;
use pedersen::{
    add_mul_protocol::AddMulProof, issuance_protocol::IssuanceProofMulti,
    opening_protocol::OpeningProofMulti, pedersen_config::Generators,
    pedersen_config::PedersenComm,
};

use ark_std::{ops::Mul, UniformRand, Zero};

/// The token representation.
#[derive(Clone)]
#[must_use]
pub struct Token<B: BoomerangConfig> {
    /// Serial Number
    id: <B as CurveConfig>::ScalarField,
    /// The value
    v: <B as CurveConfig>::ScalarField,
    /// User's secret key
    sk: <B as CurveConfig>::ScalarField,
    /// Random value
    r: <B as CurveConfig>::ScalarField,
    /// gens: the generators of the committed values.
    pub gens: Generators<B>,
}

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

/// Issuance Protocol
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
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
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
    /// id: the serial number value.
    id: Option<<B as CurveConfig>::ScalarField>,
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

        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_0, v, key_pair.x, r_0];

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
            r: r_0,
        };

        Self {
            m1,
            m3: None,
            c: None,
            id: None,
        }
    }

    pub fn generate_issuance_m3<T: RngCore + CryptoRng>(
        c_m: IssuanceC<B>,
        s_m: IssuanceS<B>,
        rng: &mut T,
    ) -> IssuanceC<B> {
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
            id: Some(id),
        }
    }

    pub fn populate_state(
        c_m: IssuanceC<B>,
        s_m: IssuanceS<B>,
        s_key_pair: ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            c_m.m3.unwrap().e,
            s_m.m4.unwrap().s,
            "message",
        );

        let commits: Vec<PedersenComm<B>> = vec![c_m.c.unwrap()];
        let sigs: Vec<SigSign<B>> = vec![sig];
        let token = Token {
            id: c_m.id.unwrap(),
            v: <B as CurveConfig>::ScalarField::zero(),
            sk: c_key_pair.x,
            r: c_m.m1.r,
            gens: c_m.m1.gens,
        };
        let tokens: Vec<Token<B>> = vec![token];

        State {
            comm_state: commits,
            sig_state: sigs,
            token_state: tokens,
            c_key_pair,
        }
    }
}

/// Collection Protocol
/// CollectionM2. This struct acts as a container for the second message of
/// the collection protocol.
#[derive(Clone)]
pub struct CollectionM2<B: BoomerangConfig> {
    /// comm: the commitment value.
    pub comm: PedersenComm<B>,
    /// gens: the generators of the commitment value.
    pub gens: Generators<B>,
    /// prev_comm: the commitment value.
    pub prev_comm: PedersenComm<B>,
    /// prev_gens: the generators of the commitment value.
    pub prev_gens: Generators<B>,
    /// pi_1: the proof value of the generated commitment.
    pub pi_1: OpeningProofMulti<B>,
    /// pi_2: the proof value of the previous commitment.
    pub pi_2: OpeningProofMulti<B>,
    /// pi_3: the proof of the tag.
    pub pi_3: AddMulProof<B>,
    /// tag: the tag value.
    pub tag: <B as CurveConfig>::ScalarField,
    /// id: the serial number value.
    pub id: <B as CurveConfig>::ScalarField,
    /// sig: the signature
    pub sig: SigSign<B>,
    /// s_proof: the proof of the commitments under the signature
    pub s_proof: SigProof<B>,
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
}

/// CollectionM4. This struct acts as a container for the fourth message of
/// the collection protocol.
#[derive(Clone)]
pub struct CollectionM4<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// CollectionC. This struct represents the collection protocol for the client.
#[derive(Clone)]
pub struct CollectionC<B: BoomerangConfig> {
    /// m2: the second message value.
    pub m2: CollectionM2<B>,
    /// m4: the fourth message value.
    pub m4: Option<CollectionM4<B>>,
    /// c: the commit value.
    c: Option<PedersenComm<B>>,
    /// id: the serial number value.
    id: Option<<B as CurveConfig>::ScalarField>,
}

impl<B: BoomerangConfig> CollectionC<B> {
    /// generate_collection_m2. This function generates the second message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn generate_collection_m2<T: RngCore + CryptoRng>(
        rng: &mut T,
        state: State<B>,
        s_m: CollectionS<B>,
        s_key_pair: ServerKeyPair<B>,
    ) -> CollectionC<B> {
        let r1 = <B as CurveConfig>::ScalarField::rand(rng);
        let id1 = <B as CurveConfig>::ScalarField::rand(rng);

        let vals: Vec<<B as CurveConfig>::ScalarField> =
            vec![id1, state.token_state[0].v, state.c_key_pair.x, r1];

        let prev_vals: Vec<<B as CurveConfig>::ScalarField> = vec![
            state.token_state[0].id,
            state.token_state[0].v,
            state.token_state[0].sk,
            state.token_state[0].r,
        ];

        let (c1, gens) = PedersenComm::new_multi(vals.clone(), rng);

        let label = b"BoomerangCollectionM2O1";
        let mut transcript = Transcript::new(label);

        let proof_1 =
            OpeningProofMulti::create(&mut transcript, rng, vals.clone(), &c1, gens.clone());

        let label1 = b"BoomerangCollectionM2O2";
        let mut transcript1 = Transcript::new(label1);

        let proof_2 = OpeningProofMulti::create(
            &mut transcript1,
            rng,
            prev_vals.clone(),
            &state.comm_state[0],
            state.token_state[0].gens.clone(),
        );

        let t_tag = state.c_key_pair.x * state.token_state[0].id;
        let tag = t_tag + s_m.m1.r2;

        let a: PedersenComm<B> = PedersenComm::new(state.c_key_pair.x, rng);
        let b: PedersenComm<B> = PedersenComm::new(state.token_state[0].id, rng);
        let c: PedersenComm<B> = PedersenComm::new(s_m.m1.r2, rng);
        let d: PedersenComm<B> = PedersenComm::new(t_tag, rng);
        let e: PedersenComm<B> = d + c;

        let proof_3 = AddMulProof::create(
            &mut transcript,
            rng,
            &state.c_key_pair.x,
            &state.token_state[0].id,
            &s_m.m1.r2,
            &a,
            &b,
            &c,
            &d,
            &e,
        );
        // TODO: add membership proof

        let sig_proof = SigProof::prove(
            rng,
            s_key_pair.s_key_pair.tag_key,
            state.sig_state[0].clone(),
            prev_vals,
            state.token_state[0].gens.generators.clone(),
            state.comm_state[0].r,
        );

        let m2 = CollectionM2 {
            comm: c1,
            gens: gens,
            prev_comm: state.comm_state[0],
            prev_gens: state.token_state[0].gens.clone(),
            pi_1: proof_1,
            pi_2: proof_2,
            pi_3: proof_3,
            tag,
            id: state.token_state[0].id,
            sig: state.sig_state[0].clone(),
            s_proof: sig_proof,
            r: r1,
        };

        Self {
            m2,
            m4: None,
            c: None,
            id: None,
        }
    }

    pub fn generate_collection_m4<T: RngCore + CryptoRng>(
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        rng: &mut T,
    ) -> CollectionC<B> {
        let m3 = s_m.m3.clone().unwrap();

        let c = m3.comm + c_m.m2.comm;
        let id = m3.id_1 + c_m.m2.id;

        let sig_chall =
            SigChall::challenge(m3.tag_key, m3.verifying_key, rng, m3.sig_commit, "message");

        let m4 = CollectionM4 { e: sig_chall };

        Self {
            m2: c_m.m2,
            m4: Some(m4),
            c: Some(c),
            id: Some(id),
        }
    }

    pub fn populate_state(
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        s_key_pair: ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            c_m.m4.unwrap().e,
            s_m.m5.unwrap().s,
            "message",
        );

        let commits: Vec<PedersenComm<B>> = vec![c_m.c.unwrap()];
        let sigs: Vec<SigSign<B>> = vec![sig];
        let token = Token {
            id: c_m.id.unwrap(),
            v: <B as CurveConfig>::ScalarField::zero(),
            sk: c_key_pair.x,
            r: c_m.m2.r,
            gens: c_m.m2.gens,
        };
        let tokens: Vec<Token<B>> = vec![token];

        State {
            comm_state: commits,
            sig_state: sigs,
            token_state: tokens,
            c_key_pair,
        }
    }
}
