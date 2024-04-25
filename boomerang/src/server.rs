//!
//! Module containing the definition of the server side of the algorithm
//!

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw},
};
use rand::{CryptoRng, RngCore};

use crate::client::{CollectionC, IssuanceC};
use crate::config::BoomerangConfig;

use acl::{
    config::KeyPair, verify::SigComm, verify::SigResp, verify::SigVerifProof, verify::SigVerify,
};
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

/// Server tag.
///
#[derive(Clone)]
struct ServerTag<B: BoomerangConfig> {
    tag: <B as CurveConfig>::ScalarField,
    id_0: <B as CurveConfig>::ScalarField,
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
            c_m.m1.gens.clone(),
        );

        if !check {
            panic!("Boomerang issuance: invalid proof");
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
#[derive(Clone)]
pub struct CollectionM1<B: BoomerangConfig> {
    /// r2: the random double-spending tag value.
    pub r2: <B as CurveConfig>::ScalarField,
}

/// CollectionM3. This struct acts as a container for the fourth message of
/// the collection protocol.
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

impl<B: BoomerangConfig> Clone for CollectionM3<B>
where
    PedersenComm<B>: Clone,
    SigComm<B>: Clone,
    <B as CurveConfig>::ScalarField: Clone,
    sw::Affine<B>: Clone,
{
    fn clone(&self) -> Self {
        CollectionM3 {
            comm: self.comm.clone(),
            sig_commit: self.sig_commit.clone(),
            id_1: self.id_1.clone(),
            verifying_key: self.verifying_key.clone(),
            tag_key: self.tag_key.clone(),
        }
    }
}

/// CollectionM5. This struct acts as a container for the fourth message of
/// the collection protocol.
#[derive(Clone)]
pub struct CollectionM5<B: BoomerangConfig> {
    /// s: the signature response value.
    pub s: SigResp<B>,
}

/// CollectionS. This struct represents the collection protocol for the server.
#[derive(Clone)]
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
            c_m.m2.sig.clone(),
            "message",
        );

        if !check {
            panic!("Boomerang collection: invalid signature");
        }

        let check2 = SigVerifProof::verify(
            c_m.m2.s_proof,
            key_pair.s_key_pair.tag_key,
            c_m.m2.sig.clone(),
        );

        if !check2 {
            panic!("Boomerang collection: invalid proof sig");
        }

        let label = b"BoomerangCollectionM2O1";
        let mut transcript = Transcript::new(label);

        let check3 = c_m
            .m2
            .pi_1
            .verify(&mut transcript, &c_m.m2.comm.comm, 4, c_m.m2.gens.clone());

        if !check3 {
            panic!("Boomerang collection: invalid proof opening 1");
        }

        let label1 = b"BoomerangCollectionM2O2";
        let mut transcript1 = Transcript::new(label1);

        let check4 = c_m.m2.pi_2.verify(
            &mut transcript1,
            &c_m.m2.prev_comm.comm,
            4,
            c_m.m2.prev_gens.clone(),
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

        let dtag: ServerTag<B> = ServerTag {
            tag: c_m.m2.tag,
            id_0: c_m.m2.id,
            r2: s_m.m1.r2,
        };

        let id_1 = <B as CurveConfig>::ScalarField::rand(rng);
        let v2 = <B as CurveConfig>::ScalarField::zero();
        let v3 = <B as CurveConfig>::ScalarField::zero();
        let vals: Vec<<B as CurveConfig>::ScalarField> = vec![id_1, v, v2, v3];

        let c1 = PedersenComm::new_multi_with_all_generators(vals.clone(), rng, c_m.m2.gens);
        let c = c1 + c_m.m2.comm;

        let sig_comm = SigComm::commit(key_pair.s_key_pair.clone(), rng, c.comm);

        let m3 = CollectionM3 {
            id_1,
            comm: c,
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
