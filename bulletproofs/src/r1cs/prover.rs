#![allow(non_snake_case)]

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::{borrow::BorrowMut, boxed::Box, mem, vec, vec::Vec, One, Zero};
use clear_on_drop::clear::Clear;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use super::{
    ConstraintSystem, LinearCombination, R1CSProof, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};

use crate::errors::R1CSError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::inner_product_proof::InnerProductProof;
use crate::transcript::TranscriptProtocol;

type DeferredConstraintFn<'g, G, T> =
    Box<dyn Fn(&mut RandomizingProver<'g, G, T>) -> Result<(), R1CSError>>;

/// A [`ConstraintSystem`] implementation for use by the prover.
///
/// The prover commits high-level variables and their blinding factors `(v, v_blinding)`,
/// allocates low-level variables and creates constraints in terms of these
/// high-level variables and low-level variables.
///
/// When all constraints are added, the proving code calls `prove`
/// which consumes the `Prover` instance, samples random challenges
/// that instantiate the randomized constraints, and creates a complete proof.
pub struct Prover<'g, G: AffineRepr, T: BorrowMut<Transcript>> {
    transcript: T,
    pc_gens: &'g PedersenGens<G>,
    /// The constraints accumulated so far.
    constraints: Vec<LinearCombination<G::ScalarField>>,
    /// Secret data
    secrets: Secrets<G>,

    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    deferred_constraints: Vec<DeferredConstraintFn<'g, G, T>>,

    /// Index of a pending multiplier that's not fully assigned yet.
    pending_multiplier: Option<usize>,
}

/// Separate struct to implement Drop trait for (for zeroing),
/// so that compiler does not prohibit us from moving the Transcript out of `prove()`.
struct Secrets<G: AffineRepr> {
    /// Stores assignments to the "left" of multiplication gates
    a_L: Vec<G::ScalarField>,
    /// Stores assignments to the "right" of multiplication gates
    a_R: Vec<G::ScalarField>,
    /// Stores assignments to the "output" of multiplication gates
    a_O: Vec<G::ScalarField>,
    /// High-level witness data (value openings to V commitments)
    v: Vec<G::ScalarField>,
    /// High-level witness data (blinding openings to V commitments)
    v_blinding: Vec<G::ScalarField>,
}

/// Prover in the randomizing phase.
///
/// Note: this type is exported because it is used to specify the associated type
/// in the public impl of a trait `ConstraintSystem`, which boils down to allowing compiler to
/// monomorphize the closures for the proving and verifying code.
/// However, this type cannot be instantiated by the user and therefore can only be used within
/// the callback provided to `specify_randomized_constraints`.
pub struct RandomizingProver<'g, G: AffineRepr, T: BorrowMut<Transcript>> {
    prover: Prover<'g, G, T>,
}

/// Overwrite secrets with null bytes when they go out of scope.
impl<G: AffineRepr> Drop for Secrets<G> {
    fn drop(&mut self) {
        self.v.clear();
        self.v_blinding.clear();

        // Important: due to how ClearOnDrop auto-implements InitializableFromZeroed
        // for T: Default, calling .clear() on Vec compiles, but does not
        // clear the content. Instead, it only clears the Vec's header.
        // Clearing the underlying buffer item-by-item will do the job, but will
        // keep the header as-is, which is fine since the header does not contain secrets.
        for e in self.a_L.iter_mut() {
            e.clear();
        }
        for e in self.a_R.iter_mut() {
            e.clear();
        }
        for e in self.a_O.iter_mut() {
            e.clear();
        }
    }
}

impl<'g, G: AffineRepr, T: BorrowMut<Transcript>> ConstraintSystem<G::ScalarField>
    for Prover<'g, G, T>
{
    fn transcript(&mut self) -> &mut Transcript {
        self.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        mut left: LinearCombination<G::ScalarField>,
        mut right: LinearCombination<G::ScalarField>,
    ) -> (
        Variable<G::ScalarField>,
        Variable<G::ScalarField>,
        Variable<G::ScalarField>,
    ) {
        // Synthesize the assignments for l,r,o
        let l = self.eval(&left);
        let r = self.eval(&right);
        let o = l * r;

        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.secrets.a_L.len());
        let r_var = Variable::MultiplierRight(self.secrets.a_R.len());
        let o_var = Variable::MultiplierOutput(self.secrets.a_O.len());
        // ... and assign them
        self.secrets.a_L.push(l);
        self.secrets.a_R.push(r);
        self.secrets.a_O.push(o);

        // Constrain l,r,o:
        left.terms.push((l_var, -G::ScalarField::one()));
        right.terms.push((r_var, -G::ScalarField::one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(
        &mut self,
        assignment: Option<G::ScalarField>,
    ) -> Result<Variable<G::ScalarField>, R1CSError> {
        let scalar = assignment.ok_or(R1CSError::MissingAssignment)?;

        match self.pending_multiplier {
            None => {
                let i = self.secrets.a_L.len();
                self.pending_multiplier = Some(i);
                self.secrets.a_L.push(scalar);
                self.secrets.a_R.push(G::ScalarField::zero());
                self.secrets.a_O.push(G::ScalarField::zero());
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                self.secrets.a_R[i] = scalar;
                self.secrets.a_O[i] = self.secrets.a_L[i] * self.secrets.a_R[i];
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(G::ScalarField, G::ScalarField)>,
    ) -> Result<
        (
            Variable<G::ScalarField>,
            Variable<G::ScalarField>,
            Variable<G::ScalarField>,
        ),
        R1CSError,
    > {
        let (l, r) = input_assignments.ok_or(R1CSError::MissingAssignment)?;
        let o = l * r;

        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.secrets.a_L.len());
        let r_var = Variable::MultiplierRight(self.secrets.a_R.len());
        let o_var = Variable::MultiplierOutput(self.secrets.a_O.len());
        // ... and assign them
        self.secrets.a_L.push(l);
        self.secrets.a_R.push(r);
        self.secrets.a_O.push(o);

        Ok((l_var, r_var, o_var))
    }

    fn multipliers_len(&self) -> usize {
        self.secrets.a_L.len()
    }

    fn constrain(&mut self, lc: LinearCombination<G::ScalarField>) {
        // TODO: check that the linear combinations are valid
        // (e.g. that variables are valid, that the linear combination evals to 0 for prover, etc).
        self.constraints.push(lc);
    }
}

impl<'g, G: AffineRepr, T: BorrowMut<Transcript>> RandomizableConstraintSystem<G::ScalarField>
    for Prover<'g, G, T>
{
    type RandomizedCS = RandomizingProver<'g, G, T>;

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }
}

impl<'g, G: AffineRepr, T: BorrowMut<Transcript>> ConstraintSystem<G::ScalarField>
    for RandomizingProver<'g, G, T>
{
    fn transcript(&mut self) -> &mut Transcript {
        self.prover.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        left: LinearCombination<G::ScalarField>,
        right: LinearCombination<G::ScalarField>,
    ) -> (
        Variable<G::ScalarField>,
        Variable<G::ScalarField>,
        Variable<G::ScalarField>,
    ) {
        self.prover.multiply(left, right)
    }

    fn allocate(
        &mut self,
        assignment: Option<G::ScalarField>,
    ) -> Result<Variable<G::ScalarField>, R1CSError> {
        self.prover.allocate(assignment)
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(G::ScalarField, G::ScalarField)>,
    ) -> Result<
        (
            Variable<G::ScalarField>,
            Variable<G::ScalarField>,
            Variable<G::ScalarField>,
        ),
        R1CSError,
    > {
        self.prover.allocate_multiplier(input_assignments)
    }

    fn multipliers_len(&self) -> usize {
        self.prover.multipliers_len()
    }

    fn constrain(&mut self, lc: LinearCombination<G::ScalarField>) {
        self.prover.constrain(lc)
    }
}

impl<'g, G: AffineRepr, T: BorrowMut<Transcript>> RandomizedConstraintSystem<G::ScalarField>
    for RandomizingProver<'g, G, T>
{
    fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
        <Transcript as TranscriptProtocol<G>>::challenge_scalar(
            self.prover.transcript.borrow_mut(),
            label,
        )
    }
}

impl<'g, G: AffineRepr, T: BorrowMut<Transcript>> Prover<'g, G, T> {
    /// Construct an empty constraint system with specified external
    /// input variables.
    ///
    /// # Inputs
    ///
    /// The `bp_gens` and `pc_gens` are generators for Bulletproofs
    /// and for the Pedersen commitments, respectively.  The
    /// [`BulletproofGens`] should have `gens_capacity` greater than
    /// the number of multiplication constraints that will eventually
    /// be added into the constraint system.
    ///
    /// The `transcript` parameter is a Merlin proof transcript.  The
    /// `ProverCS` holds onto the `&mut Transcript` until it consumes
    /// itself during [`ProverCS::prove`], releasing its borrow of the
    /// transcript.  This ensures that the transcript cannot be
    /// altered except by the `ProverCS` before proving is complete.
    ///
    /// # Returns
    ///
    /// Returns a new `Prover` instance.
    pub fn new(pc_gens: &'g PedersenGens<G>, mut transcript: T) -> Self {
        <Transcript as TranscriptProtocol<G>>::r1cs_domain_sep(transcript.borrow_mut());

        Prover {
            pc_gens,
            transcript,
            secrets: Secrets {
                v: Vec::new(),
                v_blinding: Vec::new(),
                a_L: Vec::new(),
                a_R: Vec::new(),
                a_O: Vec::new(),
            },
            constraints: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Creates commitment to a high-level variable and adds it to the transcript.
    ///
    /// # Inputs
    ///
    /// The `v` and `v_blinding` parameters are openings to the
    /// commitment to the external variable for the constraint
    /// system.  Passing the opening (the value together with the
    /// blinding factor) makes it possible to reference pre-existing
    /// commitments in the constraint system.  All external variables
    /// must be passed up-front, so that challenges produced by
    /// [`ConstraintSystem::challenge_scalar`] are bound to the
    /// external variables.
    ///
    /// # Returns
    ///
    /// Returns a pair of a Pedersen commitment (as a compressed Ristretto point),
    /// and a [`Variable`] corresponding to it, which can be used to form constraints.
    pub fn commit(
        &mut self,
        v: G::ScalarField,
        v_blinding: G::ScalarField,
    ) -> (G, Variable<G::ScalarField>) {
        let i = self.secrets.v.len();
        self.secrets.v.push(v);
        self.secrets.v_blinding.push(v_blinding);

        // Add the commitment to the transcript.
        let V = self.pc_gens.commit(v, v_blinding);
        self.transcript.borrow_mut().append_point(b"V", &V);

        (V, Variable::Committed(i))
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV)
    /// ```
    /// where `w{L,R,O}` is \\( z \cdot z^Q \cdot W_{L,R,O} \\).
    #[allow(clippy::complexity)]
    fn flattened_constraints(
        &mut self,
        z: &G::ScalarField,
    ) -> (
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
    ) {
        let n = self.secrets.a_L.len();
        let m = self.secrets.v.len();

        let mut wL = vec![G::ScalarField::zero(); n];
        let mut wR = vec![G::ScalarField::zero(); n];
        let mut wO = vec![G::ScalarField::zero(); n];
        let mut wV = vec![G::ScalarField::zero(); m];

        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var {
                    Variable::MultiplierLeft(i) => {
                        wL[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierRight(i) => {
                        wR[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierOutput(i) => {
                        wO[*i] += exp_z * coeff;
                    }
                    Variable::Committed(i) => {
                        wV[*i] -= exp_z * coeff;
                    }
                    Variable::One() => {
                        // The prover doesn't need to handle constant terms
                    }
                    _ => {}
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV)
    }

    fn eval(&self, lc: &LinearCombination<G::ScalarField>) -> G::ScalarField {
        lc.terms
            .iter()
            .map(|(var, coeff)| {
                *coeff
                    * match var {
                        Variable::MultiplierLeft(i) => self.secrets.a_L[*i],
                        Variable::MultiplierRight(i) => self.secrets.a_R[*i],
                        Variable::MultiplierOutput(i) => self.secrets.a_O[*i],
                        Variable::Committed(i) => self.secrets.v[*i],
                        Variable::One() => G::ScalarField::one(),
                        _ => G::ScalarField::zero(),
                    }
            })
            .sum()
    }

    /// Calls all remembered callbacks with an API that
    /// allows generating challenge scalars.
    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        // Clear the pending multiplier (if any) because it was committed into A_L/A_R/S.
        self.pending_multiplier = None;

        if self.deferred_constraints.is_empty() {
            <Transcript as TranscriptProtocol<G>>::r1cs_1phase_domain_sep(
                self.transcript.borrow_mut(),
            );
            Ok(self)
        } else {
            <Transcript as TranscriptProtocol<G>>::r1cs_2phase_domain_sep(
                self.transcript.borrow_mut(),
            );
            // Note: the wrapper could've used &mut instead of ownership,
            // but specifying lifetimes for boxed closures is not going to be nice,
            // so we move the self into wrapper and then move it back out afterwards.
            let mut callbacks = mem::take(&mut self.deferred_constraints);
            let mut wrapped_self = RandomizingProver { prover: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.prover)
        }
    }

    /// Consume this `ConstraintSystem` to produce a proof.
    pub fn prove<R: CryptoRng + RngCore>(
        self,
        prng: &mut R,
        bp_gens: &BulletproofGens<G>,
    ) -> Result<R1CSProof<G>, R1CSError> {
        self.prove_and_return_transcript(prng, bp_gens)
            .map(|(proof, _transcript)| proof)
    }

    /// Consume this `ConstraintSystem` to produce a proof. Returns the proof and the transcript passed in `Prover::new`.
    pub fn prove_and_return_transcript<R: CryptoRng + RngCore>(
        mut self,
        prng: &mut R,
        bp_gens: &BulletproofGens<G>,
    ) -> Result<(R1CSProof<G>, T), R1CSError> {
        use crate::util;
        use ark_std::iter;

        // Commit a length _suffix_ for the number of high-level variables.
        // We cannot do this in advance because user can commit variables one-by-one,
        // but this suffix provides safe disambiguation because each variable
        // is prefixed with a separate label.
        self.transcript
            .borrow_mut()
            .append_u64(b"m", self.secrets.v.len() as u64);

        // Create a `TranscriptRng` from the high-level witness data
        //
        // The prover wants to rekey the RNG with its witness data.
        //
        // This consists of the high level witness data (the v's and
        // v_blinding's), as well as the low-level witness data (a_L,
        // a_R, a_O).  Since the low-level data should (hopefully) be
        // determined by the high-level data, it doesn't give any
        // extra entropy for reseeding the RNG.
        //
        // Since the v_blindings should be random scalars (in order to
        // protect the v's in the commitments), we don't gain much by
        // committing the v's as well as the v_blinding's.
        let mut rng = {
            let mut builder = self.transcript.borrow_mut().build_rng();

            // Commit the blinding factors for the input wires
            for v_b in &self.secrets.v_blinding {
                let mut bytes = Vec::new();
                v_b.serialize_uncompressed(&mut bytes).unwrap();
                builder = builder.rekey_with_witness_bytes(b"v_blinding", &bytes);
            }

            builder.finalize(prng)
        };

        // Commit to the first-phase low-level witness variables.
        let n1 = self.secrets.a_L.len();

        if bp_gens.gens_capacity < n1 {
            return Err(R1CSError::InvalidGeneratorsLength);
        }

        // We are performing a single-party circuit proof, so party index is 0.
        let gens = bp_gens.share(0);

        let i_blinding1 = G::ScalarField::rand(&mut rng);
        let o_blinding1 = G::ScalarField::rand(&mut rng);
        let s_blinding1 = G::ScalarField::rand(&mut rng);

        let mut s_L1: Vec<G::ScalarField> =
            (0..n1).map(|_| G::ScalarField::rand(&mut rng)).collect();
        let mut s_R1: Vec<G::ScalarField> =
            (0..n1).map(|_| G::ScalarField::rand(&mut rng)).collect();

        // A_I = <a_L, G> + <a_R, H> + i_blinding * B_blinding
        let A_I1 = G::Group::msm(
            &iter::once(&self.pc_gens.B_blinding)
                .chain(gens.G(n1))
                .chain(gens.H(n1))
                .cloned()
                .collect::<Vec<G>>(),
            &iter::once(&i_blinding1)
                .chain(self.secrets.a_L.iter())
                .chain(self.secrets.a_R.iter())
                .copied()
                .collect::<Vec<G::ScalarField>>(),
        )
        .unwrap()
        .into_affine();

        // A_O = <a_O, G> + o_blinding * B_blinding
        let A_O1 = G::Group::msm(
            &iter::once(&self.pc_gens.B_blinding)
                .chain(gens.G(n1))
                .cloned()
                .collect::<Vec<G>>(),
            &iter::once(&o_blinding1)
                .chain(self.secrets.a_O.iter())
                .copied()
                .collect::<Vec<G::ScalarField>>(),
        )
        .unwrap()
        .into_affine();

        // S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
        let S1 = G::Group::msm(
            &iter::once(&self.pc_gens.B_blinding)
                .chain(gens.G(n1))
                .chain(gens.H(n1))
                .cloned()
                .collect::<Vec<G>>(),
            &iter::once(&s_blinding1)
                .chain(s_L1.iter())
                .chain(s_R1.iter())
                .copied()
                .collect::<Vec<G::ScalarField>>(),
        )
        .unwrap()
        .into_affine();

        let transcript = self.transcript.borrow_mut();
        transcript.append_point(b"A_I1", &A_I1);
        transcript.append_point(b"A_O1", &A_O1);
        transcript.append_point(b"S1", &S1);

        // Process the remaining constraints.
        self = self.create_randomized_constraints()?;

        // Pad zeros to the next power of two (or do that implicitly when creating vectors)

        // If the number of multiplications is not 0 or a power of 2, then pad the circuit.
        let n = self.secrets.a_L.len();
        let n2 = n - n1;
        let padded_n = self.secrets.a_L.len().next_power_of_two();
        let pad = padded_n - n;

        if bp_gens.gens_capacity < padded_n {
            return Err(R1CSError::InvalidGeneratorsLength);
        }

        // Commit to the second-phase low-level witness variables

        let has_2nd_phase_commitments = n2 > 0;

        let (i_blinding2, o_blinding2, s_blinding2) = if has_2nd_phase_commitments {
            (
                G::ScalarField::rand(&mut rng),
                G::ScalarField::rand(&mut rng),
                G::ScalarField::rand(&mut rng),
            )
        } else {
            (
                G::ScalarField::zero(),
                G::ScalarField::zero(),
                G::ScalarField::zero(),
            )
        };

        let mut s_L2: Vec<G::ScalarField> =
            (0..n2).map(|_| G::ScalarField::rand(&mut rng)).collect();
        let mut s_R2: Vec<G::ScalarField> =
            (0..n2).map(|_| G::ScalarField::rand(&mut rng)).collect();

        let (A_I2, A_O2, S2) = if has_2nd_phase_commitments {
            (
                // A_I = <a_L, G> + <a_R, H> + i_blinding * B_blinding
                G::Group::msm(
                    &iter::once(&self.pc_gens.B_blinding)
                        .chain(gens.G(n).skip(n1))
                        .chain(gens.H(n).skip(n1))
                        .cloned()
                        .collect::<Vec<G>>(),
                    &iter::once(&i_blinding2)
                        .chain(self.secrets.a_L.iter().skip(n1))
                        .chain(self.secrets.a_R.iter().skip(n1))
                        .copied()
                        .collect::<Vec<G::ScalarField>>(),
                )
                .unwrap()
                .into_affine(),
                // A_O = <a_O, G> + o_blinding * B_blinding
                G::Group::msm(
                    &iter::once(&self.pc_gens.B_blinding)
                        .chain(gens.G(n).skip(n1))
                        .cloned()
                        .collect::<Vec<G>>(),
                    &iter::once(&o_blinding2)
                        .chain(self.secrets.a_O.iter().skip(n1))
                        .copied()
                        .collect::<Vec<G::ScalarField>>(),
                )
                .unwrap()
                .into_affine(),
                // S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
                G::Group::msm(
                    &iter::once(&self.pc_gens.B_blinding)
                        .chain(gens.G(n).skip(n1))
                        .chain(gens.H(n).skip(n1))
                        .cloned()
                        .collect::<Vec<G>>(),
                    &iter::once(&s_blinding2)
                        .chain(s_L2.iter())
                        .chain(s_R2.iter())
                        .copied()
                        .collect::<Vec<G::ScalarField>>(),
                )
                .unwrap()
                .into_affine(),
            )
        } else {
            // Since we are using zero blinding factors and
            // there are no variables to commit,
            // the commitments _must_ be identity points,
            // so we can hardcode them saving 3 mults+compressions.
            (G::zero(), G::zero(), G::zero())
        };

        let transcript = self.transcript.borrow_mut();
        transcript.append_point(b"A_I2", &A_I2);
        transcript.append_point(b"A_O2", &A_O2);
        transcript.append_point(b"S2", &S2);

        // 4. Compute blinded vector polynomials l(x) and r(x)

        let y: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"y");
        let z = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"z");

        let (wL, wR, wO, wV) = self.flattened_constraints(&z);

        let mut l_poly = util::VecPoly3::<G>::zero(n);
        let mut r_poly = util::VecPoly3::<G>::zero(n);

        // y^n starting at n=0
        let mut exp_y_iter = util::exp_iter::<G>(y);
        let y_inv = y.inverse().unwrap();
        let exp_y_inv = util::exp_iter::<G>(y_inv)
            .take(padded_n)
            .collect::<Vec<_>>();

        let sLsR = s_L1
            .iter()
            .chain(s_L2.iter())
            .zip(s_R1.iter().chain(s_R2.iter()));
        for (i, (sl, sr)) in sLsR.enumerate() {
            // y^i -> y^(i+1)
            let exp_y = exp_y_iter
                .next()
                .expect("exponentional iterator shouldn't terminate");
            // l_poly.0 = 0
            // l_poly.1 = a_L + y^-n * (z * z^Q * W_R)
            l_poly.1[i] = self.secrets.a_L[i] + exp_y_inv[i] * wR[i];
            // l_poly.2 = a_O
            l_poly.2[i] = self.secrets.a_O[i];
            // l_poly.3 = s_L
            l_poly.3[i] = *sl;
            // r_poly.0 = (z * z^Q * W_O) - y^n
            r_poly.0[i] = wO[i] - exp_y;
            // r_poly.1 = y^n * a_R + (z * z^Q * W_L)
            r_poly.1[i] = exp_y * self.secrets.a_R[i] + wL[i];
            // r_poly.2 = 0
            // r_poly.3 = y^n * s_R
            r_poly.3[i] = exp_y * sr;
        }

        let t_poly = util::VecPoly3::special_inner_product(&l_poly, &r_poly);

        let t_1_blinding = G::ScalarField::rand(&mut rng);
        let t_3_blinding = G::ScalarField::rand(&mut rng);
        let t_4_blinding = G::ScalarField::rand(&mut rng);
        let t_5_blinding = G::ScalarField::rand(&mut rng);
        let t_6_blinding = G::ScalarField::rand(&mut rng);

        let T_1 = self.pc_gens.commit(t_poly.t1, t_1_blinding);
        let T_3 = self.pc_gens.commit(t_poly.t3, t_3_blinding);
        let T_4 = self.pc_gens.commit(t_poly.t4, t_4_blinding);
        let T_5 = self.pc_gens.commit(t_poly.t5, t_5_blinding);
        let T_6 = self.pc_gens.commit(t_poly.t6, t_6_blinding);

        let transcript = self.transcript.borrow_mut();
        transcript.append_point(b"T_1", &T_1);
        transcript.append_point(b"T_3", &T_3);
        transcript.append_point(b"T_4", &T_4);
        transcript.append_point(b"T_5", &T_5);
        transcript.append_point(b"T_6", &T_6);

        let u = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"u");
        let x = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x");

        // t_2_blinding = <z*z^Q, W_V * v_blinding>
        // in the t_x_blinding calculations, line 76.
        let t_2_blinding: G::ScalarField = wV
            .iter()
            .zip(self.secrets.v_blinding.iter())
            .map(|(c, v_blinding)| *v_blinding * c)
            .sum();

        let t_blinding_poly = util::Poly6::<G> {
            t1: t_1_blinding,
            t2: t_2_blinding,
            t3: t_3_blinding,
            t4: t_4_blinding,
            t5: t_5_blinding,
            t6: t_6_blinding,
        };

        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);
        let mut l_vec = l_poly.eval(x);
        // Pad out to the nearest power of two with zeros
        l_vec.resize(padded_n, G::ScalarField::zero());

        let mut r_vec = r_poly.eval(x);
        // Pad out with additional powers of y
        // XXX this should refer to the notes to explain why this is correct
        r_vec.resize_with(padded_n, || {
            let exp_y = exp_y_iter
                .next()
                .expect("exponentional iterator shouldn't terminate");
            -exp_y
        });

        let i_blinding = i_blinding1 + u * i_blinding2;
        let o_blinding = o_blinding1 + u * o_blinding2;
        let s_blinding = s_blinding1 + u * s_blinding2;

        let e_blinding = x * (i_blinding + x * (o_blinding + x * s_blinding));

        <Transcript as TranscriptProtocol<G>>::append_scalar(transcript, b"t_x", &t_x);
        <Transcript as TranscriptProtocol<G>>::append_scalar(
            transcript,
            b"t_x_blinding",
            &t_x_blinding,
        );
        <Transcript as TranscriptProtocol<G>>::append_scalar(
            transcript,
            b"e_blinding",
            &e_blinding,
        );

        // Get a challenge value to combine statements for the IPP
        let w: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"w");
        let Q = self.pc_gens.B.mul_bigint(w.into_bigint());

        let G_factors = iter::repeat(G::ScalarField::one())
            .take(n1)
            .chain(iter::repeat(u).take(n2 + pad))
            .collect::<Vec<_>>();
        let H_factors = exp_y_inv
            .into_iter()
            .zip(G_factors.iter())
            .map(|(y, u_or_1)| y * u_or_1)
            .collect::<Vec<_>>();

        let ipp_proof = InnerProductProof::create(
            transcript,
            &Q.into_affine(),
            &G_factors,
            &H_factors,
            gens.G(padded_n).cloned().collect(),
            gens.H(padded_n).cloned().collect(),
            l_vec,
            r_vec,
        );

        // We do not yet have a ClearOnDrop wrapper for Vec<Fr>.
        // When PR 202 [1] is merged, we can simply wrap s_L and s_R at the point of creation.
        // [1] https://github.com/dalek-cryptography/curve25519-dalek/pull/202
        for scalar in s_L1
            .iter_mut()
            .chain(s_L2.iter_mut())
            .chain(s_R1.iter_mut())
            .chain(s_R2.iter_mut())
        {
            scalar.clear();
        }
        let proof = R1CSProof {
            A_I1,
            A_O1,
            S1,
            A_I2,
            A_O2,
            S2,
            T_1,
            T_3,
            T_4,
            T_5,
            T_6,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        };
        Ok((proof, self.transcript))
    }
}
