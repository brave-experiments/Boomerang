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
use crate::server::{
    CollectionM1, CollectionM3, CollectionM5, IssuanceM2, IssuanceM4, ServerKeyPair, SpendVerifyM1,
    SpendVerifyM3, SpendVerifyM5,
};

use acl::{sign::SigChall, sign::SigProof, sign::SigSign};
use merlin::Transcript;
use pedersen::{
    add_mul_protocol::AddMulProof, issuance_protocol::IssuanceProofMulti,
    opening_protocol::OpeningProofMulti, pedersen_config::Generators,
    pedersen_config::PedersenComm,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::Mul, UniformRand, Zero};

use crate::utils::rewards::*;

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
}

/// Issuance Protocol
/// IssuanceM1. This struct acts as a container for the first message of
/// the issuance protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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

/// IssuanceM3. This struct acts as a container for the thrid message of
/// the issuance protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceM3<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// IssuanceStateC. This struct represents the issuance protocol for the client.
#[derive(Clone)]
pub struct IssuanceStateC<B: BoomerangConfig> {
    /// Serial Number
    id_0: <B as CurveConfig>::ScalarField,
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
    /// comm: the commitment value.
    comm: PedersenComm<B>,
    /// gens: the generators of the committed values.
    gens: Generators<B>,
    /// c: the commit value.
    c: PedersenComm<B>,
    /// id: the serial number value.
    id: <B as CurveConfig>::ScalarField,
    /// e: the signature challenge value.
    e: SigChall<B>,
}

impl<B: BoomerangConfig> IssuanceStateC<B> {
    /// Creates a new instance of `IssuanceStateC` with default values.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            id_0: <B as CurveConfig>::ScalarField::zero(),
            r: <B as CurveConfig>::ScalarField::zero(),
            comm: PedersenComm::default(),
            gens: Generators::default(),
            c: PedersenComm::default(),
            id: <B as CurveConfig>::ScalarField::zero(),
            e: SigChall::default(),
        }
    }

    /// generate_issuance_m1. This function generates the first message of the Issuance Protocol.
    /// # Arguments
    /// * `key_pair` - the client's keypair.
    /// * `rng` - the source of randomness.
    pub fn generate_issuance_m1<T: RngCore + CryptoRng>(
        key_pair: &UKeyPair<B>,
        state: &mut IssuanceStateC<B>,
        rng: &mut T,
    ) -> IssuanceM1<B> {
        let id_0 = <B as CurveConfig>::ScalarField::rand(rng);
        let v = <B as CurveConfig>::ScalarField::zero(); // the token starts with 0
        let r_0 = <B as CurveConfig>::ScalarField::rand(rng);
        // TODO: the j value should be set

        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_0, v, key_pair.x, r_0];
        let (c1, gens) = PedersenComm::new_multi(&vals, rng);

        let label = b"BoomerangM1";
        let mut transcript = Transcript::new(label);
        let proof = IssuanceProofMulti::create(&mut transcript, rng, &vals, &c1, &gens);

        state.id_0 = id_0;
        state.r = r_0;
        state.gens = gens.clone();
        state.comm = c1;

        IssuanceM1 {
            comm: c1,
            pi_issuance: proof,
            u_pk: key_pair.public_key,
            len: vals.len(),
            gens,
        }
    }

    /// generate_issuance_m2. This function generates the second message of the Issuance Protocol.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `rng` - the source of randomness.
    pub fn generate_issuance_m3<T: RngCore + CryptoRng>(
        s_m: &IssuanceM2<B>,
        state: &mut IssuanceStateC<B>,
        rng: &mut T,
    ) -> IssuanceM3<B> {
        let c = s_m.comm + state.comm;
        let id = s_m.id_1 + state.id_0;

        let sig_chall = SigChall::challenge(
            s_m.tag_key,
            s_m.verifying_key,
            rng,
            s_m.sig_commit,
            "message",
        );

        let m3 = IssuanceM3 {
            e: sig_chall.clone(),
        };

        state.c = c;
        state.id = id;
        state.e = sig_chall.clone();

        m3
    }

    /// populate_state. This function populates the local state for the client.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    /// * `c_key_pair` - the client's keypair.
    pub fn populate_state(
        s_m: &IssuanceM4<B>,
        state: &mut IssuanceStateC<B>,
        s_key_pair: &ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            &state.e,
            &s_m.s,
            "message",
        );

        // The comm_state
        let commits: Vec<PedersenComm<B>> = vec![state.c];
        // The sig_state
        let sigs: Vec<SigSign<B>> = vec![sig];
        // The state: which contains the tokens
        let token = Token {
            id: state.id,
            v: <B as CurveConfig>::ScalarField::zero(),
            sk: c_key_pair.x,
            r: state.r,
            gens: state.gens.clone(),
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
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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
    /// tag_commits: the commits for the tag proof
    pub tag_commits: Vec<PedersenComm<B>>,
}

/// CollectionM4. This struct acts as a container for the fourth message of
/// the collection protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionM4<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// CollectionStateC. This struct represents the collection protocol for the client.
#[derive(Clone)]
pub struct CollectionStateC<B: BoomerangConfig> {
    /// c: the final commit value.
    c: PedersenComm<B>,
    /// id: the serial number value.
    id: <B as CurveConfig>::ScalarField,
    /// val: the underlying value.
    val: <B as CurveConfig>::ScalarField,
    /// comm: the initial commitment value.
    comm: PedersenComm<B>,
    /// gens: the generators of the commitment value.
    gens: Generators<B>,
    /// id_0: the serial number value.
    id_0: <B as CurveConfig>::ScalarField,
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
    /// val: the underlying value of the token.
    val_0: <B as CurveConfig>::ScalarField,
    /// e: the signature challenge value.
    e: SigChall<B>,
}

impl<B: BoomerangConfig> CollectionStateC<B> {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            c: PedersenComm::default(),
            id: <B as CurveConfig>::ScalarField::zero(),
            val: <B as CurveConfig>::ScalarField::zero(),
            comm: PedersenComm::default(),
            gens: Generators::default(),
            id_0: <B as CurveConfig>::ScalarField::zero(),
            r: <B as CurveConfig>::ScalarField::zero(),
            val_0: <B as CurveConfig>::ScalarField::zero(),
            e: SigChall::default(),
        }
    }

    /// generate_collection_m2. This function generates the second message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `state` - the local client state.
    /// * `s_m` - the received server message.
    /// * `col_state` - the tmp local client state.
    /// * `s_key_pair` - the server's keypair.
    pub fn generate_collection_m2<T: RngCore + CryptoRng>(
        rng: &mut T,
        state: State<B>,
        s_m: &CollectionM1<B>,
        col_state: &mut CollectionStateC<B>,
        s_key_pair: &ServerKeyPair<B>,
    ) -> CollectionM2<B> {
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

        let (c1, gens) = PedersenComm::new_multi(&vals, rng);

        let label = b"BoomerangCollectionM2O1";
        let mut transcript = Transcript::new(label);
        let proof_1 = OpeningProofMulti::create(&mut transcript, rng, &vals, &c1, &gens);

        let label1 = b"BoomerangCollectionM2O2";
        let mut transcript1 = Transcript::new(label1);
        let proof_2 = OpeningProofMulti::create(
            &mut transcript1,
            rng,
            &prev_vals,
            &state.comm_state[0],
            &state.token_state[0].gens,
        );

        let t_tag = state.c_key_pair.x * state.token_state[0].id;
        let tag = t_tag + s_m.r2;

        let a: PedersenComm<B> = PedersenComm::new(state.c_key_pair.x, rng);
        let b: PedersenComm<B> = PedersenComm::new(state.token_state[0].id, rng);
        let c: PedersenComm<B> = PedersenComm::new(s_m.r2, rng);
        let d: PedersenComm<B> = PedersenComm::new(t_tag, rng);
        let e: PedersenComm<B> = d + c;

        let label2 = b"BoomerangCollectionM2AM2";
        let mut transcript2 = Transcript::new(label2);
        let proof_3 = AddMulProof::create(
            &mut transcript2,
            rng,
            &state.c_key_pair.x,
            &state.token_state[0].id,
            &s_m.r2,
            &a,
            &b,
            &c,
            &d,
            &e,
        );

        let tag_commits: Vec<PedersenComm<B>> = vec![a, b, c, d, e];
        // TODO: add membership proof

        let sig_proof = SigProof::prove(
            rng,
            s_key_pair.s_key_pair.tag_key,
            &state.sig_state[0],
            &prev_vals,
            &state.token_state[0].gens.generators,
            state.comm_state[0].r,
        );

        col_state.id_0 = id1;
        col_state.val_0 = state.token_state[0].v;
        col_state.comm = c1;
        col_state.r = r1;
        col_state.gens = gens.clone();

        CollectionM2 {
            comm: c1,
            gens: gens.clone(),
            prev_comm: state.comm_state[0],
            prev_gens: state.token_state[0].gens.clone(),
            pi_1: proof_1,
            pi_2: proof_2,
            pi_3: proof_3,
            tag,
            id: id1,
            sig: state.sig_state[0].clone(),
            s_proof: sig_proof,
            tag_commits,
        }
    }

    /// generate_collection_m4. This function generates the fourth message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    pub fn generate_collection_m4<T: RngCore + CryptoRng>(
        rng: &mut T,
        col_state: &mut CollectionStateC<B>,
        s_m: &CollectionM3<B>,
    ) -> CollectionM4<B> {
        let c = s_m.comm + col_state.comm;
        let id = s_m.id_1 + col_state.id_0;
        let val = s_m.val + col_state.val_0;

        let sig_chall = SigChall::challenge(
            s_m.tag_key,
            s_m.verifying_key,
            rng,
            s_m.sig_commit,
            "message",
        );

        col_state.id = id;
        col_state.val = val;
        col_state.c = c;
        col_state.e = sig_chall.clone();

        CollectionM4 {
            e: sig_chall.clone(),
        }
    }

    /// populate_state. This function re-populates the local state for the client.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    /// * `c_key_pair` - the client's keypair.
    pub fn populate_state(
        col_state: &mut CollectionStateC<B>,
        s_m: &CollectionM5<B>,
        s_key_pair: &ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            &col_state.e,
            &s_m.s,
            "message",
        );

        let commits: Vec<PedersenComm<B>> = vec![col_state.c];
        let sigs: Vec<SigSign<B>> = vec![sig];
        let token = Token {
            id: col_state.id,
            v: col_state.val,
            sk: c_key_pair.x,
            r: col_state.r,
            gens: col_state.gens.clone(),
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

/// Spending/Verification Protocol

/// SpendVerifyM2. This struct acts as a container for the second message of
/// the spendverify protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyM2<B: BoomerangConfig> {
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
    /// pi_4: the sub proof.
    pub pi_4: SubProof<B>,
    /// pi_5: the membership proof.
    /// tag: the tag value.
    pub tag: <B as CurveConfig>::ScalarField,
    /// id: the serial number value.
    pub id: <B as CurveConfig>::ScalarField,
    /// sig: the signature
    pub sig: SigSign<B>,
    /// s_proof: the proof of the commitments under the signature
    pub s_proof: SigProof<B>,
    /// tag_commits: the commits for the tag proof
    pub tag_commits: Vec<PedersenComm<B>>,
    /// spend_state: the values to spend
    pub spend_state: Vec<<B as CurveConfig>::ScalarField>,
}

/// SpendVerifyM4. This struct acts as a container for the fourth message of
/// the spendverify protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyM4<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// SpendVerifyC. This struct represents the spendverify protocol for the client.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyStateC<B: BoomerangConfig> {
    /// c: the commit value.
    c: PedersenComm<B>,
    /// id: the serial number value.
    id: <B as CurveConfig>::ScalarField,
    /// val: the underlying value.
    val: <B as CurveConfig>::ScalarField,
    /// comm: the initial commitment value.
    comm: PedersenComm<B>,
    /// gens: the generators of the committed values.
    gens: Generators<B>,
    /// id_0: the current serial number value.
    id_0: <B as CurveConfig>::ScalarField,
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
    /// val_0: the underlying current value of the token.
    val_0: <B as CurveConfig>::ScalarField,
    /// e: the signature challenge value.
    e: SigChall<B>,
    /// spend_state: the spent values.
    spend_state: Vec<<B as CurveConfig>::ScalarField>,
}

impl<B: BoomerangConfig> SpendVerifyStateC<B> {
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self {
            c: PedersenComm::default(),
            id: <B as CurveConfig>::ScalarField::zero(),
            val: <B as CurveConfig>::ScalarField::zero(),
            comm: PedersenComm::default(),
            gens: Generators::default(),
            id_0: <B as CurveConfig>::ScalarField::zero(),
            r: <B as CurveConfig>::ScalarField::zero(),
            val_0: <B as CurveConfig>::ScalarField::zero(),
            e: SigChall::default(),
            spend_state: Vec::default(),
        }
    }

    /// generate_spendverify_m2. This function generates the second message of
    /// the Spend/Verify Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `state` - the local client state.
    /// * `s_state` - the tmp client state.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    /// * `spend_state` - the values to spend passed as a vector.
    pub fn generate_spendverify_m2<T: RngCore + CryptoRng>(
        rng: &mut T,
        state: State<B>,
        s_state: &mut SpendVerifyStateC<B>,
        s_m: &SpendVerifyM1<B>,
        s_key_pair: &ServerKeyPair<B>,
        spend_state: Vec<<B as CurveConfig>::ScalarField>,
    ) -> SpendVerifyM2<B> {
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

        let (c1, gens) = PedersenComm::new_multi(&vals, rng);

        let label = b"BoomerangSpendVerifyM2O1";
        let mut transcript = Transcript::new(label);
        let proof_1 = OpeningProofMulti::create(&mut transcript, rng, &vals, &c1, &gens);

        let label1 = b"BoomerangSpendVerifyM2O2";
        let mut transcript1 = Transcript::new(label1);
        let proof_2 = OpeningProofMulti::create(
            &mut transcript1,
            rng,
            &prev_vals,
            &state.comm_state[0],
            &state.token_state[0].gens,
        );

        let t_tag = state.c_key_pair.x * state.token_state[0].id;
        let tag = t_tag + s_m.r2;

        let a: PedersenComm<B> = PedersenComm::new(state.c_key_pair.x, rng);
        let b: PedersenComm<B> = PedersenComm::new(state.token_state[0].id, rng);
        let c: PedersenComm<B> = PedersenComm::new(s_m.r2, rng);
        let d: PedersenComm<B> = PedersenComm::new(t_tag, rng);
        let e: PedersenComm<B> = d + c;

        let label2 = b"BoomerangSpendVerifyM2AM2";
        let mut transcript2 = Transcript::new(label2);
        let proof_3 = AddMulProof::create(
            &mut transcript2,
            rng,
            &state.c_key_pair.x,
            &state.token_state[0].id,
            &s_m.r2,
            &a,
            &b,
            &c,
            &d,
            &e,
        );

        // Calculate the sub_proof
        let spend = state.token_state[0].v - spend_state[0];

        let mut compressed_bytes = Vec::new();
        spend.serialize_compressed(&mut compressed_bytes).unwrap();

        let spend_u64 = match extract_u64_from_compressed_data(&compressed_bytes) {
            Ok(value) => value,
            Err(_e) => {
                panic!("Boomerang verification: failed to serialise")
            }
        };

        let sub_proof = SubProof::prove(spend_u64, rng);

        let tag_commits: Vec<PedersenComm<B>> = vec![a, b, c, d, e];
        // TODO: add membership proof

        let sig_proof = SigProof::prove(
            rng,
            s_key_pair.s_key_pair.tag_key,
            &state.sig_state[0],
            &prev_vals,
            &state.token_state[0].gens.generators,
            state.comm_state[0].r,
        );

        s_state.r = r1;
        s_state.val_0 = state.token_state[0].v;
        s_state.spend_state = spend_state.clone();
        s_state.comm = c1;
        s_state.id_0 = id1;
        s_state.gens = gens.clone();

        SpendVerifyM2 {
            comm: c1,
            gens,
            prev_comm: state.comm_state[0],
            prev_gens: state.token_state[0].gens.clone(),
            pi_1: proof_1,
            pi_2: proof_2,
            pi_3: proof_3,
            pi_4: sub_proof,
            tag,
            id: id1,
            sig: state.sig_state[0].clone(),
            s_proof: sig_proof,
            tag_commits,
            spend_state: spend_state.clone(),
        }
    }

    pub fn generate_spendverify_m4<T: RngCore + CryptoRng>(
        rng: &mut T,
        s_state: &mut SpendVerifyStateC<B>,
        s_m: &SpendVerifyM3<B>,
    ) -> SpendVerifyM4<B> {
        // Verify rewards proof
        let reward_proof = &s_m.pi_reward;
        let check = reward_proof.verify(&s_state.spend_state);
        if check.is_err() {
            panic!("Boomerang verification: reward proof verification failed")
        }

        // The other way around to handle the negative
        let c = s_state.comm - s_m.comm;
        let id = s_state.id_0 - s_m.id_1;
        let val = s_state.val_0 - s_m.val;

        let sig_chall = SigChall::challenge(
            s_m.tag_key,
            s_m.verifying_key,
            rng,
            s_m.sig_commit,
            "message",
        );

        s_state.id = id;
        s_state.val = val;
        s_state.c = c;
        s_state.e = sig_chall.clone();

        SpendVerifyM4 { e: sig_chall }
    }

    pub fn populate_state(
        s_state: &mut SpendVerifyStateC<B>,
        s_m: &SpendVerifyM5<B>,
        s_key_pair: &ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            &s_state.e,
            &s_m.s,
            "message",
        );

        let commits: Vec<PedersenComm<B>> = vec![s_state.c];
        let sigs: Vec<SigSign<B>> = vec![sig];
        let token = Token {
            id: s_state.id,
            v: s_state.val,
            sk: c_key_pair.x,
            r: s_state.r,
            gens: s_state.gens.clone(),
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
