use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use ark_serialize::CanonicalDeserialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};
use std::ops;

pub trait PedersenConfig: SWCurveConfig {
    /// Second generator that's used in Pedersen commitments.
    const GENERATOR2: sw::Affine<Self>;

    /// The curve type that maps to this PedersenConfig.
    /// For example, for T256 it would be P256.
    /// This curve type needs to be both a CurveConfig (so we can access the ScalarField / BaseField
    /// structures) and a SWCurveConfig (so we can access the generators).
    type OCurve: CurveConfig + SWCurveConfig;

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

    /// make_challenge_from_buffer. This function accepts a challenge slice (ideally produced by a transcript)
    /// and converts it into an element of Self::ScalarField.
    /// This function exists primarily to circumvent an API issue with Merlin.
    /// * `chal_buf` - a slice of bytes (representing a serialised curve point), to be used to
    ///                make a element of the ScalarField.
    /// Returns a scalar field element.
    fn make_challenge_from_buffer(chal_buf: &[u8]) -> <Self as CurveConfig>::ScalarField {
        <Self as CurveConfig>::ScalarField::deserialize_compressed(chal_buf).unwrap()
    }

    /// make_commitment_from_other. This function accepts an element `val` of OCurve::BaseField and
    /// forms a commitment C = val * g + r*h, where `g` and `h` are generators of the Self::Curve.
    /// This function uses the supplied rng to produce the random value `r`.
    /// # Arguments
    /// * `val` - the value to which we are committing.
    /// * `rng` - the random number generator that is being used. This must be a cryptographically secure RNG.
    fn make_commitment_from_other<T: RngCore + CryptoRng>(
        val: <<Self as PedersenConfig>::OCurve as CurveConfig>::BaseField,
        rng: &mut T,
    ) -> PedersenComm<Self> {
        PedersenComm::new(Self::from_ob_to_sf(val), rng)
    }

    /// OGENERATOR2. This acts as a second generator for OCurve. The reason why this
    /// exists is to allow Pedersen Commitments over OCurve to be easy to form.
    const OGENERATOR2: sw::Affine<Self::OCurve>;
}

#[derive(Copy, Clone)]
/// PedersenComm. This struct acts as a convenient wrapper for Pedersen Commitments.
/// At a high-level, this struct is meant to be used whilst producing Pedersen Commitments
/// on the side of the Prover. Namely, this struct carries around the commitment (as a point, `comm`)
/// and the associated randomness. Any serialised proofs should solely use `comm` in their transcripts /
/// serialisations.
pub struct PedersenComm<P: PedersenConfig> {
    /// comm: the point which acts as the commitment.
    pub comm: sw::Affine<P>,
    /// r: the randomness used to generate `comm`. Should not be serialised.
    pub r: <P as CurveConfig>::ScalarField,
}

impl<P: PedersenConfig> ops::Add<PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Add<&PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Add<&PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Add<PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn add(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() + rhs.comm).into(),
            r: self.r + rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<&PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<&PedersenComm<P>> for PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: &PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> ops::Sub<PedersenComm<P>> for &PedersenComm<P> {
    type Output = PedersenComm<P>;

    fn sub(self, rhs: PedersenComm<P>) -> PedersenComm<P> {
        Self::Output {
            comm: (self.comm.into_group() - rhs.comm).into(),
            r: self.r - rhs.r,
        }
    }
}

impl<P: PedersenConfig> PedersenComm<P> {
    /// new. This function accepts a ScalarField element `x` and an rng, returning a Pedersen Commitment
    /// to `x`.
    /// # Arguments
    /// * `x` - the value that is committed to.
    /// * `rng` - the random number generator used to produce the randomness. Must be cryptographically
    /// secure.
    /// Returns a new Pedersen Commitment to `x`.
    pub fn new<T: RngCore + CryptoRng>(x: <P as CurveConfig>::ScalarField, rng: &mut T) -> Self {
        Self::new_with_generators(x, rng, &<P as SWCurveConfig>::GENERATOR, &P::GENERATOR2)
    }

    /// new_with_generator. This function accepts a ScalarField element `x`, an `rng`,
    /// and two generators (`g`, `q`) and returns a Pedersen Commitment C = xg + rq. Here `r` is
    /// the produced randomness.
    /// # Arguments
    /// * `x` - the value that is committed to.
    /// * `rng` - the random number generator used to produce the randomness. Must be cryptographically
    /// secure.
    /// * `g` - a generator of `P`'s scalar field.
    /// * `q` - a distinct generator of `P`'s scalar field.
    /// Returns a new commitment to `x`.
    pub fn new_with_generators<T: RngCore + CryptoRng>(
        x: <P as CurveConfig>::ScalarField,
        rng: &mut T,
        g: &sw::Affine<P>,
        q: &sw::Affine<P>,
    ) -> Self {
        // Returns a new pedersen commitment using fixed generators.
        // N.B First check that `g != q`.
        assert!(g != q);
        let r = <P as CurveConfig>::ScalarField::rand(rng);
        Self {
            comm: (g.mul(x) + q.mul(r)).into_affine(),
            r,
        }
    }

    /// new_with_both. This function returns a new Pedersen Commitment to `x` with randomness
    /// `r` (i.e the commitment is C = xg + rq, where `g` and `q` are pre-defined generators.
    /// # Arguments
    /// * `x` - the value that is being committed to.
    /// * `r` - the randomness to use.
    /// Returns a new commitment to `x`.
    pub fn new_with_both(
        x: <P as CurveConfig>::ScalarField,
        r: <P as CurveConfig>::ScalarField,
    ) -> Self {
        Self {
            comm: (<P as SWCurveConfig>::GENERATOR.mul(x) + P::GENERATOR2.mul(r)).into_affine(),
            r,
        }
    }
}
