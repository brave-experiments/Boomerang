//!
//! Module containing the definition of the server side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
};
use rand::{CryptoRng, RngCore};

use crate::client::{CollectionC, IssuanceC, SpendVerifyC};
use crate::config::BoomerangConfig;

use acl::{
    config::KeyPair, verify::SigComm, verify::SigResp, verify::SigVerifProof, verify::SigVerify,
};
use merlin::Transcript;
use pedersen::pedersen_config::PedersenComm;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, Zero};

use rewards_proof::{RewardsGenerators, RewardsProof};

/// Server keypair.
///
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ServerKeyPair<B: BoomerangConfig> {
    /// Public key
    pub s_key_pair: KeyPair<B>,
}

/// Server tag.
///
#[derive(Clone)]
#[allow(unused_variables)]
struct ServerTag<B: BoomerangConfig> {
    #[allow(dead_code)]
    tag: <B as CurveConfig>::ScalarField,
    #[allow(dead_code)]
    id_0: <B as CurveConfig>::ScalarField,
    #[allow(dead_code)]
    r2: <B as CurveConfig>::ScalarField,
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

/// Issuance protocol
/// IssuanceM2. This struct acts as a container for the second message of
/// the issuance protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceM4<B: BoomerangConfig> {
    /// s: the signature response value.
    pub s: SigResp<B>,
}

/// IssuanceS. This struct represents the issuance protocol for the server.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceS<B: BoomerangConfig> {
    /// m2: the second message value.
    pub m2: IssuanceM2<B>,
    /// m4: the fourth message value.
    pub m4: Option<IssuanceM4<B>>,
}

impl<B: BoomerangConfig> IssuanceS<B> {
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
            &c_m.m1.gens,
        );

        if !check {
            panic!("Boomerang issuance: invalid proof");
        }

        let id_1 = <B as CurveConfig>::ScalarField::rand(rng);

        let v1 = <B as CurveConfig>::ScalarField::zero();
        let v2 = <B as CurveConfig>::ScalarField::zero();
        let v3 = <B as CurveConfig>::ScalarField::zero();
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_1, v1, v2, v3];

        let c1 = PedersenComm::new_multi_with_all_generators(&vals, rng, &c_m.m1.gens);

        let c = c1 + c_m.m1.comm;

        let sig_comm = SigComm::commit(key_pair.s_key_pair.clone(), rng, c.comm);
        let m2 = IssuanceM2 {
            id_1,
            comm: c1,
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

/// Collection protocol
/// CollectionM1. This struct acts as a container for the first message of
/// the collection protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionM1<B: BoomerangConfig> {
    /// r2: the random double-spending tag value.
    pub r2: <B as CurveConfig>::ScalarField,
}

/// CollectionM3. This struct acts as a container for the fourth message of
/// the collection protocol.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionM3<B: BoomerangConfig> {
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

impl<B: BoomerangConfig> Clone for CollectionM3<B> {
    fn clone(&self) -> Self {
        CollectionM3 {
            comm: self.comm,
            sig_commit: self.sig_commit,
            id_1: self.id_1,
            verifying_key: self.verifying_key,
            tag_key: self.tag_key,
        }
    }
}

/// CollectionM5. This struct acts as a container for the fourth message of
/// the collection protocol.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionM5<B: BoomerangConfig> {
    /// s: the signature response value.
    pub s: SigResp<B>,
}

/// CollectionS. This struct represents the collection protocol for the server.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionS<B: BoomerangConfig> {
    /// m1: the first message value.
    pub m1: CollectionM1<B>,
    /// m3: the third message value.
    pub m3: Option<CollectionM3<B>>,
    /// m5: the fifth message value.
    pub m5: Option<CollectionM5<B>>,
}

impl<B: BoomerangConfig> CollectionS<B> {
    /// generate_collection_m1. This function generates the first message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn generate_collection_m1<T: RngCore + CryptoRng>(rng: &mut T) -> CollectionS<B> {
        let r2 = <B as CurveConfig>::ScalarField::rand(rng);

        let m1 = CollectionM1 { r2 };

        Self {
            m1,
            m3: None,
            m5: None,
        }
    }

    pub fn generate_collection_m3<T: RngCore + CryptoRng>(
        rng: &mut T,
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        key_pair: ServerKeyPair<B>,
        v: <B as CurveConfig>::ScalarField,
    ) -> CollectionS<B> {
        let check = SigVerify::verify(
            key_pair.s_key_pair.verifying_key,
            key_pair.s_key_pair.tag_key,
            &c_m.m2.sig,
            "message",
        );

        if !check {
            panic!("Boomerang collection: invalid signature");
        }

        let check2 = SigVerifProof::verify(
            c_m.m2.s_proof,
            key_pair.s_key_pair.tag_key,
            &c_m.m2.sig,
        );

        if !check2 {
            panic!("Boomerang collection: invalid proof sig");
        }

        let label = b"BoomerangCollectionM2O1";
        let mut transcript = Transcript::new(label);

        let check3 = c_m
            .m2
            .pi_1
            .verify(&mut transcript, &c_m.m2.comm.comm, 4, &c_m.m2.gens);

        if !check3 {
            panic!("Boomerang collection: invalid proof opening 1");
        }

        let label1 = b"BoomerangCollectionM2O2";
        let mut transcript1 = Transcript::new(label1);

        let check4 = c_m.m2.pi_2.verify(
            &mut transcript1,
            &c_m.m2.prev_comm.comm,
            4,
            &c_m.m2.prev_gens,
        );

        if !check4 {
            panic!("Boomerang collection: invalid proof opening 2");
        }

        let label2 = b"BoomerangCollectionM2AM2";
        let mut transcript2 = Transcript::new(label2);

        let check5 = c_m.m2.pi_3.verify(
            &mut transcript2,
            &c_m.m2.tag_commits[0].comm,
            &c_m.m2.tag_commits[1].comm,
            &c_m.m2.tag_commits[2].comm,
            &c_m.m2.tag_commits[3].comm,
            &c_m.m2.tag_commits[4].comm,
        );

        if !check5 {
            panic!("Boomerang collection: invalid proof of tag");
        }

        #[allow(unused_variables)]
        let dtag: ServerTag<B> = ServerTag {
            tag: c_m.m2.tag,
            id_0: c_m.m2.id,
            r2: s_m.m1.r2,
        }; // TODO: this needs to be stored by the server and check regularly

        let id_1 = <B as CurveConfig>::ScalarField::rand(rng);
        let v2 = <B as CurveConfig>::ScalarField::zero();
        let v3 = <B as CurveConfig>::ScalarField::zero();
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_1, v, v2, v3];

        let c1 = PedersenComm::new_multi_with_all_generators(&vals, rng, &c_m.m2.gens);
        let c = c1 + c_m.m2.comm;

        let sig_comm = SigComm::commit(key_pair.s_key_pair.clone(), rng, c.comm);

        let m3 = CollectionM3 {
            id_1,
            comm: c1,
            sig_commit: sig_comm,
            verifying_key: key_pair.s_key_pair.verifying_key,
            tag_key: key_pair.s_key_pair.tag_key,
        };

        Self {
            m1: s_m.m1,
            m3: Some(m3),
            m5: None,
        }
    }

    pub fn generate_collection_m5(
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        key_pair: ServerKeyPair<B>,
    ) -> CollectionS<B> {
        let sig_resp = SigResp::respond(
            key_pair.s_key_pair.clone(),
            s_m.m3.clone().unwrap().sig_commit,
            c_m.m4.unwrap().e,
        );
        let m5 = CollectionM5 { s: sig_resp };

        Self {
            m1: s_m.m1,
            m3: s_m.m3,
            m5: Some(m5),
        }
    }
}

/// Spending/Verification protocol
/// SpendVerifyM1. This struct acts as a container for the first message of
/// the spendverify protocol.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyM1<B: BoomerangConfig> {
    /// r2: the random double-spending tag value.
    pub r2: <B as CurveConfig>::ScalarField,
}

impl<B: BoomerangConfig> Clone for SpendVerifyM1<B> {
    fn clone(&self) -> Self {
        Self { r2: self.r2 }
    }
}

/// SpendVerifyM3. This struct acts as a container for the third message of
/// the spendverify protocol.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyM3<B: BoomerangConfig> {
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
    /// Rewards proof
    pub pi_reward: RewardsProof<B>,
}

impl<B: BoomerangConfig> Clone for SpendVerifyM3<B> {
    fn clone(&self) -> Self {
        Self {
            comm: self.comm,
            sig_commit: self.sig_commit,
            id_1: self.id_1,
            verifying_key: self.verifying_key,
            tag_key: self.tag_key,
            pi_reward: self.pi_reward.clone(),
        }
    }
}

/// SpendVerifyM5. This struct acts as a container for the fifth message of
/// the spendverify protocol.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyM5<B: BoomerangConfig> {
    /// s: the signature response value.
    pub s: SigResp<B>,
}

impl<B: BoomerangConfig> Clone for SpendVerifyM5<B> {
    fn clone(&self) -> Self {
        Self { s: self.s }
    }
}

/// SpendVerifyS. This struct represents the spendverify protocol for the server.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SpendVerifyS<B: BoomerangConfig> {
    /// m1: the first message value.
    pub m1: SpendVerifyM1<B>,
    /// m3: the third message value.
    pub m3: Option<SpendVerifyM3<B>>,
    /// m5: the fifth message value.
    pub m5: Option<SpendVerifyM5<B>>,
}

impl<B: BoomerangConfig> Clone for SpendVerifyS<B> {
    fn clone(&self) -> Self {
        Self {
            m1: self.m1.clone(),
            m3: self.m3.clone(),
            m5: self.m5.clone(),
        }
    }
}

impl<B: BoomerangConfig> SpendVerifyS<B> {
    /// generate_spendverify_m1. This function generates the first message of
    /// the SpendVerify Protocol.
    /// # Arguments
    /// * `inter` - the intermediate values to use.
    pub fn generate_spendverify_m1<T: RngCore + CryptoRng>(rng: &mut T) -> SpendVerifyS<B> {
        let r2 = <B as CurveConfig>::ScalarField::rand(rng);

        let m1 = SpendVerifyM1 { r2 };

        Self {
            m1,
            m3: None,
            m5: None,
        }
    }

    pub fn generate_spendverify_m3<T: RngCore + CryptoRng>(
        rng: &mut T,
        c_m: SpendVerifyC<B>,
        s_m: SpendVerifyS<B>,
        key_pair: ServerKeyPair<B>,
        v: <B as CurveConfig>::ScalarField,
        state_vector: Vec<u64>,
        policy_vector: Vec<u64>,
    ) -> SpendVerifyS<B> {
        // verify signature
        let check = SigVerify::verify(
            key_pair.s_key_pair.verifying_key,
            key_pair.s_key_pair.tag_key,
            &c_m.m2.sig,
            "message",
        );

        if !check {
            panic!("Boomerang spend/verify: invalid signature");
        }

        // verify signature proof
        let check2 = SigVerifProof::verify(
            c_m.m2.s_proof,
            key_pair.s_key_pair.tag_key,
            &c_m.m2.sig,
        );

        if !check2 {
            panic!("Boomerang spend/verify: invalid proof sig");
        }

        // verify opening proof \pi_open(tk0)
        let mut transcript_p1 = Transcript::new(b"BoomerangSpendVerifyM2O1");
        let check3 = c_m.m2.pi_1.verify(
            &mut transcript_p1,
            &c_m.m2.comm.comm,
            4,
            &c_m.m2.gens,
        );

        if !check3 {
            panic!("Boomerang spend/verify: invalid proof opening 1");
        }

        // verify opening proof \pi_open(tk0')
        let mut transcript_p2 = Transcript::new(b"BoomerangSpendVerifyM2O2");
        let check4 = c_m.m2.pi_2.verify(
            &mut transcript_p2,
            &c_m.m2.prev_comm.comm,
            4,
            &c_m.m2.prev_gens,
        );

        /*if !check4 {
            panic!("Boomerang spend/verify: invalid proof opening 2");
        }*/

        // verify tag proof
        let mut transcript_p3 = Transcript::new(b"BoomerangSpendVerifyM2O3");
        let check5 = c_m.m2.pi_3.verify(
            &mut transcript_p3,
            &c_m.m2.tag_commits[0].comm,
            &c_m.m2.tag_commits[1].comm,
            &c_m.m2.tag_commits[2].comm,
            &c_m.m2.tag_commits[3].comm,
            &c_m.m2.tag_commits[4].comm,
        );

        if !check5 {
            panic!("Boomerang spend/verify: invalid proof of tag");
        }

        // TODO membership proof verification \pi_member
        //let mut transcript_p4 = Transcript::new(b"BoomerangSpendVerifyM2O4");
        let check6 = true;

        if !check6 {
            panic!("Boomerang spend/verify: invalid membership proof");
        }

        // server tag
        #[allow(unused_variables)]
        let dtag: ServerTag<B> = ServerTag {
            tag: c_m.m2.tag,
            id_0: c_m.m2.id,
            r2: s_m.m1.r2,
        }; // TODO: this needs to be stored by the server and check regularly

        // ID0''
        let id0dashdash = <B as CurveConfig>::ScalarField::rand(rng);

        // Create Pedersen commitment
        // C0'' = PC.Comm(ID0'', v, 0, 0)
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![
            id0dashdash,
            v,
            <B as CurveConfig>::ScalarField::zero(),
            <B as CurveConfig>::ScalarField::zero(),
        ];
        let c0dashdash =
            PedersenComm::new_multi_with_all_generators(&vals, rng, &c_m.m2.gens);

        // C0 = C0' - C0''
        let c0 = c_m.m2.comm - c0dashdash;

        // create signature commitment
        // R = BSA.comm(sk_IC, C0)
        // sig_comm = R
        let sig_comm = SigComm::commit(key_pair.s_key_pair.clone(), rng, c0.comm);

        // Compute reward state
        let reward: u64 = state_vector
            .iter()
            .zip(policy_vector.iter())
            .flat_map(|(x, y)| x.checked_mul(*y))
            .sum();

        let state_scalar: Vec<<B as CurveConfig>::ScalarField> = state_vector
            .clone()
            .into_iter()
            .map(<B as CurveConfig>::ScalarField::from)
            .collect();
        let policy_vector_scalar: Vec<<B as CurveConfig>::ScalarField> = policy_vector
            .clone()
            .into_iter()
            .map(<B as CurveConfig>::ScalarField::from)
            .collect();

        // Generate \pi_reward
        let reward_generators = RewardsGenerators::create();
        let reward_proof = RewardsProof::create(
            reward_generators,
            reward,
            state_scalar,
            policy_vector_scalar,
        );

        // construct message 3
        let m3 = SpendVerifyM3 {
            comm: c0dashdash,
            sig_commit: sig_comm,
            id_1: id0dashdash,
            verifying_key: key_pair.s_key_pair.verifying_key,
            tag_key: key_pair.s_key_pair.tag_key,
            pi_reward: reward_proof,
        };

        Self {
            m1: s_m.m1,
            m3: Some(m3),
            m5: None,
        }
    }

    pub fn generate_spendverify_m5(
        c_m: SpendVerifyC<B>,
        s_m: SpendVerifyS<B>,
        key_pair: ServerKeyPair<B>,
    ) -> SpendVerifyS<B> {
        let sig_resp = SigResp::respond(
            key_pair.s_key_pair.clone(),
            s_m.m3.clone().unwrap().sig_commit,
            c_m.m4.unwrap().e,
        );
        let m5 = SpendVerifyM5 { s: sig_resp };

        Self {
            m1: s_m.m1,
            m3: s_m.m3,
            m5: Some(m5),
        }
    }
}
