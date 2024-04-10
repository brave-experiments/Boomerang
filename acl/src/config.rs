use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use ark_std::{ops::Mul, UniformRand};
use digest::{ExtendableOutputDirty, Update, XofReader};
use rand::{CryptoRng, RngCore};
use sha3::Shake256;

pub trait ACLConfig: SWCurveConfig {
    /// The curve type that maps to this Config.
    /// For example, for T256 it would be P256.
    /// This curve type needs to be both a CurveConfig (so we can access the ScalarField / BaseField
    /// structures) and a SWCurveConfig (so we can access the generators).
    type OCurve: CurveConfig + SWCurveConfig;

    /// The security level associated with this particular Config. This should
    /// be set from the user side. For NIST curves, a prime of bit size |p| provides approximately
    /// |p|/2 bits of security.
    const SECPARAM: usize;

    /// Second generator that's used in Pedersen commitments. Corresponds to H.
    const GENERATOR2: sw::Affine<Self>;
}

/// StateSignatureComm. This struct acts as a convenient wrapper for Pedersen Commitments.
/// At a high-level, this struct is meant to be used whilst producing Pedersen Commitments
/// on the side of the Prover. Namely, this struct carries around the commitment (as a point, `comm`)
/// and the associated randomness. Any serialised proofs should solely use `comm` in their transcripts /
/// serialisations.
pub struct StateSignatureComm<P: ACLConfig> {
    /// comm: the multi-commitment to the attributes.
    pub comm: sw::Affine<P>,
    /// r: the randomness used to generate `comm`. Should not be serialised.
    pub r: <P as CurveConfig>::ScalarField,
}

/// ACL keypair.
///
#[derive(Clone, PartialEq)]
#[must_use]
pub struct KeyPair<A: ACLConfig> {
    /// Public key
    pub verifying_key: sw::Affine<A>,

    /// Tag public key
    pub tag_key: sw::Affine<A>,

    /// Private component x
    x: <A as CurveConfig>::ScalarField,
}

impl<A: ACLConfig> KeyPair<A> {
    pub fn affine_from_bytes_tai(bytes: &[u8]) -> sw::Affine<A> {
        extern crate crypto;
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        for i in 0..=u8::max_value() {
            let mut sha = Sha3::sha3_256();
            sha.input(bytes);
            sha.input(&[i]);
            let mut buf = [0u8; 32];
            sha.result(&mut buf);
            let res = sw::Affine::<A>::from_random_bytes(&buf);
            if let Some(point) = res {
                return point;
            }
        }
        panic!()
    }

    /// Generate a new ACL keypair
    #[inline]
    pub fn generate<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let x = <A as CurveConfig>::ScalarField::rand(rng);

        let label = [b'G', 0, 0, 0, 0];
        let mut shake = Shake256::default();
        shake.update(b"Tag Public Key");
        shake.update(label);
        let mut reader = shake.finalize_xof_dirty();

        let mut uniform_bytes = [0u8; 64];
        reader.read(&mut uniform_bytes);
        let rest = Self::affine_from_bytes_tai(&uniform_bytes);

        Self {
            tag_key: rest,
            verifying_key: (<A as SWCurveConfig>::GENERATOR.mul(x)).into_affine(),
            x,
        }
    }

    /// ACL public key
    pub const fn verifying_key(&self) -> &sw::Affine<A> {
        &self.verifying_key
    }

    /// ACL private key
    pub const fn signing_key(&self) -> &<A as CurveConfig>::ScalarField {
        &self.x
    }
}
