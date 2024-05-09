use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AffineRepr, CurveGroup,
};

use ark_serialize::CanonicalDeserialize;
use ark_std::{ops::Mul, UniformRand};
use rand::{CryptoRng, RngCore};
use std::ops;

use digest::{ExtendableOutputDirty, Update, XofReader};
use sha3::Shake256;

pub trait PedersenConfig: SWCurveConfig {
    /// Second generator that's used in Pedersen commitments. Corresponds to H.
    const GENERATOR2: sw::Affine<Self>;

    /// The curve type that maps to this PedersenConfig.
    /// For example, for T256 it would be P256.
    /// This curve type needs to be both a CurveConfig (so we can access the ScalarField / BaseField
    /// structures) and a SWCurveConfig (so we can access the generators).
    type OCurve: CurveConfig + SWCurveConfig;

    /// The security level associated with this particular Pedersen Config. This should
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

    /// make_single_bit_challenge. This function accepts a single bit value `v` and returns:
    /// * -1 (in the ScalarField) if `v == 0`.
    /// *  1 (in the ScalarField) if `v == 1`.
    /// For any other value of `v` this function panics.
    /// # Arguments
    /// * `v` - the single bit challenge.
    fn make_single_bit_challenge(v: u8) -> <Self as CurveConfig>::ScalarField;

    /// OGENERATOR2. This acts as a second generator for OCurve. The reason why this
    /// exists is to allow Pedersen Commitments over OCurve to be easy to form.
    const OGENERATOR2: sw::Affine<Self::OCurve>;

    /// CP1. This constant is the representation of "1" in the ScalarField of `Self`.
    const CP1: Self::ScalarField;

    /// CM1. This constant is the representation of "-1" in the ScalarField of `Self`.
    const CM1: Self::ScalarField;

    /// create_commitments_to_coords. This function accepts a series of affine points (from the underyling OCurve)
    /// and creates commitments to each co-ordinate of each point, returning the results as a tuple.
    /// The formed commitments are commitments over the relevant T Curve.
    /// # Arguments
    /// * `a`: one of the summands.
    /// * `b`: the other summand.
    /// * `t`: the target point (i.e `t = a + b`).
    /// * `rng`: the RNG that is used. Must be cryptographically secure.
    #[allow(clippy::type_complexity)]
    fn create_commitments_to_coords<T: RngCore + CryptoRng>(
        a: sw::Affine<<Self as PedersenConfig>::OCurve>,
        b: sw::Affine<<Self as PedersenConfig>::OCurve>,
        t: sw::Affine<<Self as PedersenConfig>::OCurve>,
        rng: &mut T,
    ) -> (
        PedersenComm<Self>,
        PedersenComm<Self>,
        PedersenComm<Self>,
        PedersenComm<Self>,
        PedersenComm<Self>,
        PedersenComm<Self>,
    ) {
        (
            Self::make_commitment_from_other(a.x, rng),
            Self::make_commitment_from_other(a.y, rng),
            Self::make_commitment_from_other(b.x, rng),
            Self::make_commitment_from_other(b.y, rng),
            Self::make_commitment_from_other(t.x, rng),
            Self::make_commitment_from_other(t.y, rng),
        )
    }

    /// get_random_p. This function is a helper function for returning a random value from
    /// the scalar field of the OCurve.
    /// # Arguments
    /// * `rng` - the random number generator used to produce the random value. Must be a cryptographically
    /// secure RNG.
    /// Returns a random scalar value from OCurve::ScalarField.
    fn get_random_p<T: RngCore + CryptoRng>(
        rng: &mut T,
    ) -> <Self::OCurve as CurveConfig>::ScalarField {
        <Self::OCurve as CurveConfig>::ScalarField::rand(rng)
    }

    /// create_commit_other. This function accepts a value (`val` ∈ OCurve::ScalarField)
    /// and produces a new Pedersen Commitment C = val*g + r*h, where `g`, `h` are public
    /// generators of OCurve and `r` is a random element of OCurve::ScalarField.
    /// # Arguments
    /// * `val - the value that is being committed to.
    /// * `rng` - the random number generator used to produce the random value. Must be a cryptographically
    /// secure RNG.
    /// Returns a new commitment to `val` as a tuple.
    fn create_commit_other<T: RngCore + CryptoRng>(
        val: &<Self::OCurve as CurveConfig>::ScalarField,
        rng: &mut T,
    ) -> (
        sw::Affine<Self::OCurve>,
        <Self::OCurve as CurveConfig>::ScalarField,
    ) {
        Self::create_commit_other_with_both(val, &Self::get_random_p(rng))
    }

    /// create_multi_commit_other. This function accepts a values (`vals` ∈ OCurve::ScalarField)
    /// and produces a new Pedersen Commitment C = (vals)*g + r*h, where `g`, `h` are public
    /// generators of OCurve and `r` is a random element of OCurve::ScalarField.
    /// # Arguments
    /// * `vals - the values that is being committed to.
    /// * `rng` - the random number generator used to produce the random value. Must be a cryptographically
    /// secure RNG.
    /// Returns a new commitment to `val` as a tuple.
    fn create_multi_commit_other<T: RngCore + CryptoRng>(
        vals: Vec<&<Self::OCurve as CurveConfig>::ScalarField>,
        rng: &mut T,
    ) -> (
        sw::Affine<Self::OCurve>,
        <Self::OCurve as CurveConfig>::ScalarField,
    ) {
        Self::create_multi_commit_other_with_both(vals, &Self::get_random_p(rng))
    }

    /// create_commit_other_with_both. This function accepts a value (`val` ∈ OCurve::ScalarField)
    /// and some randomness (`r` ∈ OCurve::ScalarField) and returns a new Pedersen Commitment C =
    /// val*g + r*h, where `g`, `h` are public generators of OCurve.
    /// # Arguments
    /// * `val - the value that is being committed to.
    /// * `r` - the randomness value.
    /// Returns a new commitment to `val` as a tuple.
    fn create_commit_other_with_both(
        val: &<Self::OCurve as CurveConfig>::ScalarField,
        r: &<Self::OCurve as CurveConfig>::ScalarField,
    ) -> (
        sw::Affine<Self::OCurve>,
        <Self::OCurve as CurveConfig>::ScalarField,
    ) {
        (
            (<Self::OCurve as SWCurveConfig>::GENERATOR * (*val) + Self::OGENERATOR2.mul(r))
                .into_affine(),
            *r,
        )
    }

    /// create_multi_commit_other_with_both. This function accepts a list of values (`vals` ∈ OCurve::ScalarField)
    /// and some randomness (`r` ∈ OCurve::ScalarField) and returns a new Pedersen Commitment C =
    /// (vals_i*g) + r*h, where `g`, `h` are public generators of OCurve.
    /// # Arguments
    /// * `vals - the values that are being committed to.
    /// * `r` - the randomness value.
    /// Returns a new commitment to `vals` as a tuple.
    fn create_multi_commit_other_with_both(
        vals: Vec<&<Self::OCurve as CurveConfig>::ScalarField>,
        r: &<Self::OCurve as CurveConfig>::ScalarField,
    ) -> (
        sw::Affine<Self::OCurve>,
        <Self::OCurve as CurveConfig>::ScalarField,
    ) {
        let mut total: <Self::OCurve as CurveConfig>::ScalarField = Default::default();

        for i in &vals {
            total += *i
        }

        let ret: sw::Affine<Self::OCurve> = ((<Self::OCurve as SWCurveConfig>::GENERATOR * total)
            + (Self::OGENERATOR2.mul(r).into_affine()))
        .into();

        (ret, *r)
    }

    /// new_other_with_both. This function accepts two values `x`, `r` ∈ OCurve::ScalarField
    /// and uses them to form a new Pedersen Commitment in Self::Curve. Namely, this function
    /// returns C = xg + rh, where `g` and `r` are publicly known generators of Self::Curve.
    /// # Arguments
    /// * `x` - the value that is being committed to.
    /// * `r` - the randomness value that is being used.
    fn new_other_with_both(
        x: &<Self::OCurve as CurveConfig>::ScalarField,
        r: &<Self::OCurve as CurveConfig>::ScalarField,
    ) -> sw::Affine<Self::OCurve> {
        (<Self::OCurve as SWCurveConfig>::GENERATOR * (*x) + Self::OGENERATOR2.mul(r)).into_affine()
    }

    /// new_other_multiple_with_both. This function accepts two values `vals`, `r` ∈ OCurve::ScalarField
    /// and uses them to form a new Pedersen Commitment in Self::Curve. Namely, this function
    /// returns C = g(vals) + rh, where `g` and `r` are publicly known generators of Self::Curve.
    /// # Arguments
    /// * `vals` - the value that is being committed to.
    /// * `r` - the randomness value that is being used.
    fn new_other_multiple_with_both(
        vals: Vec<&<Self::OCurve as CurveConfig>::ScalarField>,
        r: &<Self::OCurve as CurveConfig>::ScalarField,
    ) -> sw::Affine<Self::OCurve> {
        let mut total: <Self::OCurve as CurveConfig>::ScalarField = Default::default();
        for i in &vals {
            total += *i
        }

        (<Self::OCurve as SWCurveConfig>::GENERATOR * total + Self::OGENERATOR2.mul(r))
            .into_affine()
    }
}

/// Generators. This structure holds the generators for a multi-commitment.
pub struct Generators<P: PedersenConfig> {
    pub generators: Vec<sw::Affine<P>>,
}

impl<P: PedersenConfig> Clone for Generators<P> {
    fn clone(&self) -> Self {
        Generators {
            generators: self.generators.clone(),
        }
    }
}

/// PedersenComm. This struct acts as a convenient wrapper for Pedersen Commitments.
/// At a high-level, this struct is meant to be used whilst producing Pedersen Commitments
/// on the side of the Prover. Namely, this struct carries around the commitment (as a point, `comm`)
/// and the associated randomness. Any serialised proofs should solely use `comm` in their transcripts /
/// serialisations.
#[derive(Debug)]
pub struct PedersenComm<P: PedersenConfig> {
    /// comm: the point which acts as the commitment.
    pub comm: sw::Affine<P>,
    /// r: the randomness used to generate `comm`. Should not be serialised.
    pub r: <P as CurveConfig>::ScalarField,
}

// This is here because #[Derive(Clone, Copy)] doesn't
// appear to work properly for generic structs...
impl<P: PedersenConfig> Copy for PedersenComm<P> {}
impl<P: PedersenConfig> Clone for PedersenComm<P> {
    fn clone(&self) -> Self {
        *self
    }
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
    pub fn get_main_generator() -> sw::Affine<P> {
        <P as SWCurveConfig>::GENERATOR
    }

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

    /// new_multi. This function accepts various ScalarField elements `val` and an rng, returning a Pedersen Commitment
    /// to `vals`.
    /// # Arguments
    /// * `vals` - the values that are committed to.
    /// * `rng` - the random number generator used to produce the randomness. Must be cryptographically
    /// secure.
    /// Returns a new Pedersen Commitment to `x`.
    pub fn new_multi<T: RngCore + CryptoRng>(
        vals: Vec<<P as CurveConfig>::ScalarField>,
        rng: &mut T,
    ) -> (Self, Generators<P>) {
        Self::new_multi_with_generators(vals, rng, &<P as SWCurveConfig>::GENERATOR, &P::GENERATOR2)
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
        // Returns a new Pedersen commitment using fixed generators.
        // N.B First check that `g != q`.
        assert!(g != q);
        let r = <P as CurveConfig>::ScalarField::rand(rng);
        Self {
            comm: (g.mul(x) + q.mul(r)).into_affine(),
            r,
        }
    }

    pub fn affine_from_bytes_tai(bytes: &[u8]) -> sw::Affine<P> {
        use sha3::{Digest, Sha3_256};
        // Try a deterministic sequence of hashes to find a valid point.
        for i in 0..=u8::max_value() {
            let mut sha = Sha3_256::new();
            Digest::update(&mut sha, bytes);
            Digest::update(&mut sha, [i]);
            let hash = sha.finalize();
            let res = sw::Affine::<P>::from_random_bytes(hash.as_slice());
            if let Some(point) = res {
                return point;
            }
        }
        panic!()
    }
    /// new_multi_with_generators. This function accepts a list of ScalarField elements `val`, an `rng`,
    /// and two generators (`g`, `q`) and returns a Pedersen Commitment C = valsg + rq. Here `r` is
    /// the produced randomness.
    /// # Arguments
    /// * `vals` - the values that are committed to.
    /// * `rng` - the random number generator used to produce the randomness. Must be cryptographically
    /// secure.
    /// * `g` - a generator of `P`'s scalar field.
    /// * `q` - a distinct generator of `P`'s scalar field.
    /// Returns a new commitment to `x`.
    pub fn new_multi_with_generators<T: RngCore + CryptoRng>(
        vals: Vec<<P as CurveConfig>::ScalarField>,
        rng: &mut T,
        g: &sw::Affine<P>,
        q: &sw::Affine<P>,
    ) -> (Self, Generators<P>) {
        // Returns a new multi pedersen commitment using fixed generators.
        // N.B First check that `g != q`.
        assert!(g != q);
        let r = <P as CurveConfig>::ScalarField::rand(rng);

        let mut gens: Vec<sw::Affine<P>> = vec![];
        gens.push(*g);

        let label = [b'G', 0, 0, 0, 0];
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);
        let mut reader = shake.finalize_xof_dirty();

        for _ in 0..vals.len() {
            let mut uniform_bytes = [0u8; 64];
            reader.read(&mut uniform_bytes);

            let rest = Self::affine_from_bytes_tai(&uniform_bytes);
            gens.push(rest);
        }

        let gens_s = Generators {
            generators: gens.clone(),
        };

        let mut total: sw::Affine<P> = sw::Affine::identity();
        for i in 0..vals.len() {
            total = (total + gens[i].mul(vals[i])).into();
        }

        (
            Self {
                comm: (total + q.mul(r)).into_affine(),
                r,
            },
            gens_s.clone(),
        )
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

    /// new_multi_with_both. This function returns a new Pedersen Commitment to `vals` with randomness
    /// `r` (i.e the commitment is C = valsg + rq, where `g` and `q` are pre-defined generators.
    /// # Arguments
    /// * `vals` - the values that are being committed to.
    /// * `r` - the randomness to use.
    /// Returns a new commitment to `x`.
    pub fn new_multi_with_both(
        vals: Vec<<P as CurveConfig>::ScalarField>,
        r: <P as CurveConfig>::ScalarField,
    ) -> (Self, Generators<P>) {
        let mut gens: Vec<sw::Affine<P>> = vec![];
        gens.push(<P as SWCurveConfig>::GENERATOR);

        let label = [b'G', 0, 0, 0, 0];
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);
        let mut reader = shake.finalize_xof_dirty();

        for _ in 1..vals.len() {
            let mut uniform_bytes = [0u8; 64];
            reader.read(&mut uniform_bytes);

            let rest = Self::affine_from_bytes_tai(&uniform_bytes);
            gens.push(rest);
        }

        let gens_s = Generators {
            generators: gens.clone(),
        };

        let mut total: sw::Affine<P> = sw::Affine::identity();
        for i in 0..gens.len() {
            total = (total + gens[i].mul(vals[i])).into();
        }

        (
            Self {
                comm: (total + P::GENERATOR2.mul(r)).into_affine(),
                r,
            },
            gens_s.clone(),
        )
    }

    /// new_multi_with_all_generators. This function accepts a list of ScalarField elements `val`, an `rng`,
    /// and a list of generators, and returns a multi Pedersen Commitment C. Here `r` is
    /// the produced randomness.
    /// # Arguments
    /// * `vals` - the values that are committed to.
    /// * `rng` - the random number generator used to produce the randomness. Must be cryptographically
    /// secure.
    /// Returns a new commitment to `x`.
    pub fn new_multi_with_all_generators<T: RngCore + CryptoRng>(
        vals: Vec<<P as CurveConfig>::ScalarField>,
        rng: &mut T,
        gens: Generators<P>,
    ) -> Self {
        // Returns a new multi pedersen commitment using fixed generators.
        let r = <P as CurveConfig>::ScalarField::rand(rng);

        let mut total: sw::Affine<P> = sw::Affine::identity();
        for (i, item) in vals.iter().enumerate() {
            total = (total + gens.generators[i].mul(item)).into();
        }

        Self {
            comm: (total + P::GENERATOR2.mul(r)).into_affine(),
            r,
        }
    }

    pub const fn commitment(&self) -> sw::Affine<P> {
        self.comm
    }
}
