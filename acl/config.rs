use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use ark_serialize::CanonicalDeserialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};
use std::ops;

pub trait ACLConfig: SWCurveConfig {
    /// A generator that's used in signature. Corresponds to H.
    const GENERATOR2: sw::Affine<Self>;

    /// A tag public key. Corresponds to Z.
    const TAGKEY: sw::Affine<Self>;

    /// The curve type that maps to this Config.
    /// For example, for T256 it would be P256.
    /// This curve type needs to be both a CurveConfig (so we can access the ScalarField / BaseField
    /// structures) and a SWCurveConfig (so we can access the generators).
    type OCurve: CurveConfig + SWCurveConfig;

    /// The security level associated with this particular Config. This should
    /// be set from the user side. For NIST curves, a prime of bit size |p| provides approximately
    /// |p|/2 bits of security.
    const SECPARAM: usize;

    /// from_oc. This function takes an `x` in OCurve's ScalarField and converts it
    /// into an element of the ScalarField of the current curve.
    /// * `x` - the element ∈ OCurve's ScalarField.
    /// Returns `x` as an element of Self::ScalarField.
    fn from_oc(
        x: <Self::OCurve as CurveConfig>::ScalarField,
    ) -> <Self as CurveConfig>::ScalarField {
        let x_bt: num_bigint::BigUint = x.into();
        <Self as CurveConfig>::ScalarField::from(x_bt)
    }

    /// from_ob_to_os. This function takes an `x` in the OCurve's BaseField and converts
    /// it into an element of the Scalar field of the OCurve.
    /// * `x` - the element ∈ OCurve's BaseField.
    /// Returns `y` ∈ OCurve's ScalarField.
    fn from_ob_to_os(
        x: <Self::OCurve as CurveConfig>::BaseField,
    ) -> <Self::OCurve as CurveConfig>::ScalarField;

    /// from_ob_to_sf. This function takes an `x` in the OCurve's BaseField and converts
    /// it into an element of the ScalarField of the current curve.
    /// * `x` - the element ∈ OCurve's BaseField.
    /// Returns `x` as an element of Self::ScalarField.
    fn from_ob_to_sf(
        x: <Self::OCurve as CurveConfig>::BaseField,
    ) -> <Self as CurveConfig>::ScalarField;

    /// from_ob_to_sf. This function takes an `x` in the OCurve's ScalarField and converts
    /// it into an element of the ScalarField of the current curve.
    /// * `x` - the element ∈ OCurve's ScalarField.
    /// Returns `x` as an element of Self::ScalarField.
    fn from_os_to_sf(
        x: <Self::OCurve as CurveConfig>::ScalarField,
    ) -> <Self as CurveConfig>::ScalarField;

    /// from_bf_to_sf. This function takes an `x` in  Self::BaseField and converts
    /// it into an element of the ScalarField of the current curve.
    /// * `x` - the element ∈ Self::BaseField.
    /// Returns `x` as an element of Self::ScalarField.
    fn from_bf_to_sf(x: <Self as CurveConfig>::BaseField) -> <Self as CurveConfig>::ScalarField;

    fn from_u64_to_sf(x: u64) -> <Self as CurveConfig>::ScalarField;
}

/// StateSignatureComm. This struct acts as a convenient wrapper for Pedersen Commitments.
/// At a high-level, this struct is meant to be used whilst producing Pedersen Commitments
/// on the side of the Prover. Namely, this struct carries around the commitment (as a point, `comm`)
/// and the associated randomness. Any serialised proofs should solely use `comm` in their transcripts /
/// serialisations.
pub struct StateSignatureComm<P: Config> {
    /// comm: the multi-commitment to the attributes.
    pub comm: sw::Affine<P>,
    /// r: the randomness used to generate `comm`. Should not be serialised.
    pub r: <P as CurveConfig>::ScalarField,
}
