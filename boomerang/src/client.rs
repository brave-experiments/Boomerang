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
use crate::server::{CollectionS, IssuanceS, ServerKeyPair, SpendVerifyS};

use acl::{sign::SigChall, sign::SigProof, sign::SigSign};
use merlin::Transcript;
use pedersen::{
    add_mul_protocol::AddMulProof, issuance_protocol::IssuanceProofMulti,
    opening_protocol::OpeningProofMulti, pedersen_config::Generators,
    pedersen_config::PedersenComm,
};

use ark_bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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
    /// Serial Number
    id_0: <B as CurveConfig>::ScalarField,
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
}

/// IssuanceM3. This struct acts as a container for the thrid message of
/// the issuance protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceM3<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// IssuanceC. This struct represents the issuance protocol for the client.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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
    /// * `key_pair` - the client's keypair.
    /// * `rng` - the source of randomness.
    pub fn generate_issuance_m1<T: RngCore + CryptoRng>(
        key_pair: UKeyPair<B>,
        rng: &mut T,
    ) -> IssuanceC<B> {
        let id_0 = <B as CurveConfig>::ScalarField::rand(rng);
        let v = <B as CurveConfig>::ScalarField::zero(); // the token starts with 0
        let r_0 = <B as CurveConfig>::ScalarField::rand(rng);
        // TODO: the j value should be set

        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_0, v, key_pair.x, r_0];
        let (c1, gens) = PedersenComm::new_multi(&vals, rng);

        let label = b"BoomerangM1";
        let mut transcript = Transcript::new(label);
        let proof = IssuanceProofMulti::create(&mut transcript, rng, &vals, &c1, &gens);

        let m1 = IssuanceM1 {
            comm: c1,
            pi_issuance: proof,
            u_pk: key_pair.public_key,
            len: vals.len(),
            gens,
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

    /// generate_issuance_m2. This function generates the second message of the Issuance Protocol.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `rng` - the source of randomness.
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

    /// populate_state. This function populates the local state for the client.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    /// * `c_key_pair` - the client's keypair.
    pub fn populate_state(
        c_m: IssuanceC<B>,
        s_m: IssuanceS<B>,
        s_key_pair: &ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            &c_m.m3.unwrap().e,
            &s_m.m4.unwrap().s,
            "message",
        );

        // The comm_state
        let commits: Vec<PedersenComm<B>> = vec![c_m.c.unwrap()];
        // The sig_state
        let sigs: Vec<SigSign<B>> = vec![sig];
        // The state: which contains the tokens
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
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
    /// val: the underlying value of the token.
    val: <B as CurveConfig>::ScalarField,
}

/// CollectionM4. This struct acts as a container for the fourth message of
/// the collection protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionM4<B: BoomerangConfig> {
    /// e: the signature challenge value.
    pub e: SigChall<B>,
}

/// CollectionC. This struct represents the collection protocol for the client.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionC<B: BoomerangConfig> {
    /// m2: the second message value.
    pub m2: CollectionM2<B>,
    /// m4: the fourth message value.
    pub m4: Option<CollectionM4<B>>,
    /// c: the commit value.
    c: Option<PedersenComm<B>>,
    /// id: the serial number value.
    id: Option<<B as CurveConfig>::ScalarField>,
    /// val: the underlying value.
    val: Option<<B as CurveConfig>::ScalarField>,
}

impl<B: BoomerangConfig> CollectionC<B> {
    /// generate_collection_m2. This function generates the second message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `state` - the local client state.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    pub fn generate_collection_m2<T: RngCore + CryptoRng>(
        rng: &mut T,
        state: State<B>,
        s_m: CollectionS<B>,
        s_key_pair: &ServerKeyPair<B>,
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
        let tag = t_tag + s_m.m1.r2;

        let a: PedersenComm<B> = PedersenComm::new(state.c_key_pair.x, rng);
        let b: PedersenComm<B> = PedersenComm::new(state.token_state[0].id, rng);
        let c: PedersenComm<B> = PedersenComm::new(s_m.m1.r2, rng);
        let d: PedersenComm<B> = PedersenComm::new(t_tag, rng);
        let e: PedersenComm<B> = d + c;

        let label2 = b"BoomerangCollectionM2AM2";
        let mut transcript2 = Transcript::new(label2);
        let proof_3 = AddMulProof::create(
            &mut transcript2,
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

        let m2 = CollectionM2 {
            comm: c1,
            gens,
            prev_comm: state.comm_state[0],
            prev_gens: state.token_state[0].gens.clone(),
            pi_1: proof_1,
            pi_2: proof_2,
            pi_3: proof_3,
            tag,
            //id: state.token_state[0].id,
            id: id1,
            sig: state.sig_state[0].clone(),
            s_proof: sig_proof,
            tag_commits,
            r: r1,
            val: state.token_state[0].v,
        };

        Self {
            m2,
            m4: None,
            c: None,
            id: None,
            val: None,
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
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
    ) -> CollectionC<B> {
        let m3 = s_m.m3.clone().unwrap();

        let c = m3.comm + c_m.m2.comm;
        let id = m3.id_1 + c_m.m2.id;
        let val = m3.val + c_m.m2.val;

        let sig_chall =
            SigChall::challenge(m3.tag_key, m3.verifying_key, rng, m3.sig_commit, "message");

        let m4 = CollectionM4 { e: sig_chall };

        Self {
            m2: c_m.m2,
            m4: Some(m4),
            c: Some(c),
            id: Some(id),
            val: Some(val),
        }
    }

    /// populate_state. This function re-populates the local state for the client.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    /// * `c_key_pair` - the client's keypair.
    pub fn populate_state(
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        s_key_pair: &ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            &c_m.m4.unwrap().e,
            &s_m.m5.unwrap().s,
            "message",
        );

        let commits: Vec<PedersenComm<B>> = vec![c_m.c.unwrap()];
        let sigs: Vec<SigSign<B>> = vec![sig];
        let token = Token {
            id: c_m.id.unwrap(),
            v: c_m.val.unwrap(),
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

/// Spending/Verification Protocol

/// SubProof. This struct acts as a container for the sub-proof.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SubProof<B: BoomerangConfig> {
    // the range proof
    pub range_proof: RangeProof<sw::Affine<B>>,
    // the pc gens for range proof
    pub range_gensp_r: PedersenGens<sw::Affine<B>>,
    // the bp gens for range proof
    pub range_gensb_r: BulletproofGens<sw::Affine<B>>,
    // the commitment of range proof
    pub r_comms: sw::Affine<B>,
}

impl<B: BoomerangConfig> Clone for SubProof<B> {
    fn clone(&self) -> Self {
        SubProof {
            range_proof: self.range_proof.clone(),
            range_gensp_r: self.range_gensp_r,
            range_gensb_r: self.range_gensb_r.clone(),
            r_comms: self.r_comms,
        }
    }
}

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
    /// r: the random double-spending tag value.
    r: <B as CurveConfig>::ScalarField,
    /// val: the underlying value of the token.
    val: <B as CurveConfig>::ScalarField,
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
pub struct SpendVerifyC<B: BoomerangConfig> {
    /// m2: the second message value.
    pub m2: SpendVerifyM2<B>,
    /// m4: the fourth message value.
    pub m4: Option<SpendVerifyM4<B>>,
    /// c: the commit value.
    c: Option<PedersenComm<B>>,
    /// id: the serial number value.
    id: Option<<B as CurveConfig>::ScalarField>,
    /// val: the underlying value.
    val: Option<<B as CurveConfig>::ScalarField>,
}

impl<B: BoomerangConfig> SpendVerifyC<B> {
    /// generate_spendverify_m2. This function generates the second message of
    /// the Spend/Verify Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `state` - the local client state.
    /// * `s_m` - the received server message.
    /// * `s_key_pair` - the server's keypair.
    /// * `spend_state` - the values to spend.
    pub fn generate_spendverify_m2<T: RngCore + CryptoRng>(
        rng: &mut T,
        state: State<B>,
        s_m: SpendVerifyS<B>,
        s_key_pair: &ServerKeyPair<B>,
        spend_state: Vec<<B as CurveConfig>::ScalarField>,
    ) -> SpendVerifyC<B> {
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
        let tag = t_tag + s_m.m1.r2;

        let a: PedersenComm<B> = PedersenComm::new(state.c_key_pair.x, rng);
        let b: PedersenComm<B> = PedersenComm::new(state.token_state[0].id, rng);
        let c: PedersenComm<B> = PedersenComm::new(s_m.m1.r2, rng);
        let d: PedersenComm<B> = PedersenComm::new(t_tag, rng);
        let e: PedersenComm<B> = d + c;

        let label2 = b"BoomerangSpendVerifyM2AM2";
        let mut transcript2 = Transcript::new(label2);
        let proof_3 = AddMulProof::create(
            &mut transcript2,
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

        // Calculate the sub_proof
        let spend = state.token_state[0].v - spend_state[0];
        // TODO: too hacky
        let mut compressed_bytes = Vec::new();
        spend.serialize_compressed(&mut compressed_bytes).unwrap();
        let spend_bytes = compressed_bytes
            .as_slice()
            .get(0..8) // Take the first 8 bytes
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap())) // Convert to u64
            .unwrap_or(0); // Default to 0 if not enough bytes
                           //let reward_bytes = reward.into_repr();
                           //let reward_array: [u8; 8] = reward_bytes[0..8].try_into();
        let max_spend = 64; // TODO: should be app specific
        let pc_gens_r: PedersenGens<sw::Affine<B>> = PedersenGens::default();
        // We instantiate with the maximum capacity
        let bp_gens_r = BulletproofGens::new(max_spend, 1);
        let mut transcript_r = Transcript::new(b"Boomerang verify sub proof");
        let blind = <B as CurveConfig>::ScalarField::rand(rng);
        let (r_proof, r_comms) = RangeProof::prove_single(
            &bp_gens_r,
            &pc_gens_r,
            &mut transcript_r,
            spend_bytes,
            &blind,
            max_spend,
        )
        .unwrap();

        let sub_proof = SubProof {
            range_proof: r_proof,
            range_gensp_r: pc_gens_r,
            range_gensb_r: bp_gens_r,
            r_comms,
        };

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

        let m2 = SpendVerifyM2 {
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
            spend_state,
            r: r1,
            val: state.token_state[0].v,
        };

        Self {
            m2,
            m4: None,
            c: None,
            id: None,
            val: None,
        }
    }

    pub fn generate_spendverify_m4<T: RngCore + CryptoRng>(
        rng: &mut T,
        c_m: SpendVerifyC<B>,
        s_m: SpendVerifyS<B>,
    ) -> SpendVerifyC<B> {
        let m3 = s_m.m3.clone().unwrap();

        // verify rewards proof
        let reward_proof = m3.pi_reward;

        let mut transcript_r = Transcript::new(b"Boomerang verify range proof");
        let max_reward = 64; // TODO: should be app specific
        let check = reward_proof.range_proof.verify_single(
            &reward_proof.range_gensb_r,
            &reward_proof.range_gensp_r,
            &mut transcript_r,
            &reward_proof.r_comms,
            max_reward,
        );
        if check.is_err() {
            panic!("Boomerang verification: reward range proof verification failed")
        }

        let g: Vec<_> = reward_proof
            .range_gensb_l
            .share(0)
            .G(1) // this is app specific
            .cloned()
            .collect::<Vec<sw::Affine<B>>>();
        let f = reward_proof.range_gensp_l.B;
        let b = reward_proof.range_gensp_l.B_blinding;
        let mut transcript_l = Transcript::new(b"Boomerang verify linear proof");

        let check2 = reward_proof.linear_proof.verify(
            &mut transcript_l,
            &reward_proof.l_comms,
            &g,
            &f,
            &b,
            c_m.m2.spend_state.clone(),
        );
        if check2.is_err() {
            panic!("Boomerang verification: reward linear proof verification failed")
        }

        // The other way around to handle the negative
        let c = c_m.m2.comm - m3.comm;
        let id = c_m.m2.id - m3.id_1;
        let val = c_m.m2.val - m3.val;

        let sig_chall =
            SigChall::challenge(m3.tag_key, m3.verifying_key, rng, m3.sig_commit, "message");

        let m4 = SpendVerifyM4 { e: sig_chall };

        Self {
            m2: c_m.m2,
            m4: Some(m4),
            c: Some(c),
            id: Some(id),
            val: Some(val),
        }
    }

    pub fn populate_state(
        c_m: SpendVerifyC<B>,
        s_m: SpendVerifyS<B>,
        s_key_pair: &ServerKeyPair<B>,
        c_key_pair: UKeyPair<B>,
    ) -> State<B> {
        let sig = SigSign::sign(
            s_key_pair.s_key_pair.verifying_key,
            s_key_pair.s_key_pair.tag_key,
            &c_m.m4.unwrap().e,
            &s_m.m5.unwrap().s,
            "message",
        );

        let commits: Vec<PedersenComm<B>> = vec![c_m.c.unwrap()];
        let sigs: Vec<SigSign<B>> = vec![sig];
        let token = Token {
            id: c_m.id.unwrap(),
            v: c_m.val.unwrap(),
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
