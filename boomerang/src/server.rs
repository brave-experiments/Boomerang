//!
//! Module containing the definition of the server side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
};
use rand::{CryptoRng, RngCore};

use crate::client::{CollectionC, IssuanceM1, IssuanceM3, SpendVerifyC};
use crate::config::BoomerangConfig;

use acl::{
    config::KeyPair, verify::SigComm, verify::SigResp, verify::SigVerifProof, verify::SigVerify,
};
use merlin::Transcript;
use pedersen::pedersen_config::PedersenComm;

use crate::utils::rewards::*;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, Zero};

use std::default::Default;
use std::fmt;

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

impl<B: BoomerangConfig> fmt::Debug for ServerKeyPair<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerKeyPair")
            .field("public_key", self.public_key())
            .field("tag_key", self.tag_key())
            .finish()
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

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuanceStateS<B: BoomerangConfig> {
    /// sig_commit: the first signature value.
    pub sig_commit: SigComm<B>,
}

impl<B: BoomerangConfig> Default for IssuanceStateS<B> {
    fn default() -> Self {
        Self {
            sig_commit: SigComm::<B>::default(), // Default value for `sig_commit`
        }
    }
}

impl<B: BoomerangConfig> IssuanceStateS<B> {
    /// generate_issuance_m2. This function generates the second message of the Issuance Protocol.
    /// # Arguments
    /// * `c_m` - the received client message.
    /// * `key_pair` - the server keypair.
    /// * `rng` - the source of randomness.
    pub fn generate_issuance_m2<T: RngCore + CryptoRng>(
        c_m: &IssuanceM1<B>,
        key_pair: &ServerKeyPair<B>,
        state: &mut IssuanceStateS<B>,
        rng: &mut T,
    ) -> IssuanceM2<B> {
        let label = b"BoomerangM1";
        let mut transcript = Transcript::new(label);
        let check = c_m.pi_issuance.verify(
            &mut transcript,
            &c_m.comm.comm,
            &c_m.u_pk,
            c_m.len,
            &c_m.gens,
        );

        if !check {
            panic!("Boomerang issuance: invalid proof");
        }

        let id_1 = <B as CurveConfig>::ScalarField::rand(rng);

        let v1 = <B as CurveConfig>::ScalarField::zero();
        let v2 = <B as CurveConfig>::ScalarField::zero();
        let v3 = <B as CurveConfig>::ScalarField::zero();
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_1, v1, v2, v3];
        let c1 = PedersenComm::new_multi_with_all_generators(&vals, rng, &c_m.gens);
        let c = c1 + c_m.comm;

        let sig_comm = SigComm::commit(&key_pair.s_key_pair, rng, c.comm);
        let m2 = IssuanceM2 {
            id_1,
            comm: c1,
            sig_commit: sig_comm,
            verifying_key: key_pair.s_key_pair.verifying_key,
            tag_key: key_pair.s_key_pair.tag_key,
        };

        state.sig_commit = sig_comm;

        m2
    }

    /// generate_issuance_m4. This function generates the fourth message of the Issuance Protocol.
    /// # Arguments
    /// * `c_m` - the client message.
    /// * `s_m` - the received server message.
    /// * `key_pair` - the server's keypair.
    pub fn generate_issuance_m4(
        c_m: &IssuanceM3<B>,
        state: &mut IssuanceStateS<B>,
        key_pair: &ServerKeyPair<B>,
    ) -> IssuanceM4<B> {
        let sig_resp = SigResp::respond(&key_pair.s_key_pair, &state.sig_commit, &c_m.e);

        IssuanceM4 { s: sig_resp }
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

/// CollectionM3. This struct acts as a container for the thrid message of
/// the collection protocol.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CollectionM3<B: BoomerangConfig> {
    /// comm: the commitment value.
    pub comm: PedersenComm<B>,
    /// sig_commit: the first signature value.
    pub sig_commit: SigComm<B>,
    /// Serial Number
    pub id_1: <B as CurveConfig>::ScalarField,
    /// Val: the value to be added
    pub val: <B as CurveConfig>::ScalarField,
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
            val: self.val,
            verifying_key: self.verifying_key,
            tag_key: self.tag_key,
        }
    }
}

/// CollectionM5. This struct acts as a container for the fifth message of
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
    pub fn generate_collection_m1<T: RngCore + CryptoRng>(rng: &mut T) -> CollectionS<B> {
        let r2 = <B as CurveConfig>::ScalarField::rand(rng);

        let m1 = CollectionM1 { r2 };

        Self {
            m1,
            m3: None,
            m5: None,
        }
    }

    /// generate_collection_m3. This function generates the thrid message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `c_m` - the received client message.
    /// * `s_m` - the server message.
    /// * `key_pair` - the server's keypair.
    /// * `v` - the value to add.
    pub fn generate_collection_m3<T: RngCore + CryptoRng>(
        rng: &mut T,
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        key_pair: &ServerKeyPair<B>,
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

        let check2 =
            SigVerifProof::verify(&c_m.m2.s_proof, key_pair.s_key_pair.tag_key, &c_m.m2.sig);
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

        // TODO: verify the membership proof
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

        let sig_comm = SigComm::commit(&key_pair.s_key_pair, rng, c.comm);

        let m3 = CollectionM3 {
            id_1,
            val: v,
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

    /// generate_collection_m5. This function generates the fifth message of
    /// the Collection Protocol.
    /// # Arguments
    /// * `c_m` - the received client message.
    /// * `s_m` - the server message.
    /// * `key_pair` - the server's keypair.
    pub fn generate_collection_m5(
        c_m: CollectionC<B>,
        s_m: CollectionS<B>,
        key_pair: &ServerKeyPair<B>,
    ) -> CollectionS<B> {
        let sig_resp = SigResp::respond(
            &key_pair.s_key_pair,
            &s_m.m3.clone().unwrap().sig_commit,
            &c_m.m4.unwrap().e,
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
    /// Val: the value to be added
    pub val: <B as CurveConfig>::ScalarField,
    /// Public key
    pub verifying_key: sw::Affine<B>,
    /// Tag public key
    pub tag_key: sw::Affine<B>,
    /// Rewards proof
    pub pi_reward: BRewardsProof<B>,
}

impl<B: BoomerangConfig> Clone for SpendVerifyM3<B> {
    fn clone(&self) -> Self {
        Self {
            comm: self.comm,
            sig_commit: self.sig_commit,
            id_1: self.id_1,
            val: self.val,
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
    pub fn generate_spendverify_m1<T: RngCore + CryptoRng>(rng: &mut T) -> SpendVerifyS<B> {
        let r2 = <B as CurveConfig>::ScalarField::rand(rng);

        let m1 = SpendVerifyM1 { r2 };

        Self {
            m1,
            m3: None,
            m5: None,
        }
    }

    /// generate_spendverify_m3. This function generates the thrid message of
    /// the Spend/Verify Protocol.
    /// # Arguments
    /// * `rng` - the source of randomness.
    /// * `c_m` - the received client message.
    /// * `s_m` - the server message.
    /// * `key_pair` - the server's keypair.
    /// * `v` - the value to be spent.
    pub fn generate_spendverify_m3<T: RngCore + CryptoRng>(
        rng: &mut T,
        c_m: SpendVerifyC<B>,
        s_m: SpendVerifyS<B>,
        key_pair: &ServerKeyPair<B>,
        policy_state: Vec<<B as CurveConfig>::ScalarField>,
    ) -> SpendVerifyS<B> {
        let check = SigVerify::verify(
            key_pair.s_key_pair.verifying_key,
            key_pair.s_key_pair.tag_key,
            &c_m.m2.sig,
            "message",
        );
        if !check {
            panic!("Boomerang spend-verify: invalid signature");
        }

        let check2 =
            SigVerifProof::verify(&c_m.m2.s_proof, key_pair.s_key_pair.tag_key, &c_m.m2.sig);
        if !check2 {
            panic!("Boomerang spend-verify: invalid proof sig");
        }

        let label = b"BoomerangSpendVerifyM2O1";
        let mut transcript = Transcript::new(label);
        let check3 = c_m
            .m2
            .pi_1
            .verify(&mut transcript, &c_m.m2.comm.comm, 4, &c_m.m2.gens);

        if !check3 {
            panic!("Boomerang spend-verify: invalid proof opening 1");
        }

        let label1 = b"BoomerangSpendVerifyM2O2";
        let mut transcript1 = Transcript::new(label1);
        let check4 = c_m.m2.pi_2.verify(
            &mut transcript1,
            &c_m.m2.prev_comm.comm,
            4,
            &c_m.m2.prev_gens,
        );
        if !check4 {
            panic!("Boomerang spend-verify: invalid proof opening 2");
        }

        let label2 = b"BoomerangSpendVerifyM2AM2";
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
            panic!("Boomerang spend-verify: invalid proof of tag");
        }

        // Verify the sub proof
        let sub_proof = c_m.m2.pi_4;

        let mut transcript_s = Transcript::new(b"Boomerang verify sub proof");
        let max_sub = 64; // TODO: should be app specific
        let check6 = sub_proof.range_proof.verify_single(
            &sub_proof.range_gensb_r,
            &sub_proof.range_gensp_r,
            &mut transcript_s,
            &sub_proof.r_comms,
            max_sub,
        );
        if check6.is_err() {
            panic!("Boomerang verification: reward range proof verification failed")
        }

        // TODO: verify the membership proof

        #[allow(unused_variables)]
        let dtag: ServerTag<B> = ServerTag {
            tag: c_m.m2.tag,
            id_0: c_m.m2.id,
            r2: s_m.m1.r2,
        }; // TODO: this needs to be stored by the server and check regularly

        let id_1 = <B as CurveConfig>::ScalarField::rand(rng);
        let v2 = <B as CurveConfig>::ScalarField::zero();
        let v3 = <B as CurveConfig>::ScalarField::zero();
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_1, c_m.m2.spend_state[0], v2, v3];

        let c1 = PedersenComm::new_multi_with_all_generators(&vals, rng, &c_m.m2.gens);

        // Compute rewards
        let (reward_u64, reward) =
            match inner_product_to_u64::<B>(&c_m.m2.spend_state, &policy_state) {
                Ok(reward_u64) => reward_u64,
                Err(_e) => {
                    panic!("Boomerang verification: failed to compute reward")
                }
            };

        let re_proof =
            match BRewardsProof::prove(&c_m.m2.spend_state, &policy_state, reward_u64, reward, rng)
            {
                Ok(proof) => proof,
                Err(_e) => {
                    panic!("Boomerang verification: failed to create rewards proof")
                }
            };

        // Only if the rewards proof was successfully done
        let c = c_m.m2.comm - c1; // The other way around to handle the negative
        let sig_comm = SigComm::commit(&key_pair.s_key_pair, rng, c.comm);

        let m3 = SpendVerifyM3 {
            id_1,
            val: c_m.m2.spend_state[0],
            comm: c1,
            sig_commit: sig_comm,
            verifying_key: key_pair.s_key_pair.verifying_key,
            tag_key: key_pair.s_key_pair.tag_key,
            pi_reward: re_proof,
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
        key_pair: &ServerKeyPair<B>,
    ) -> SpendVerifyS<B> {
        let sig_resp = SigResp::respond(
            &key_pair.s_key_pair,
            &s_m.m3.as_ref().unwrap().sig_commit,
            &c_m.m4.unwrap().e,
        );
        let m5 = SpendVerifyM5 { s: sig_resp };

        Self {
            m1: s_m.m1,
            m3: s_m.m3,
            m5: Some(m5),
        }
    }
}
