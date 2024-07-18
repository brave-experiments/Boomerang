#![allow(non_snake_case)]

use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::{
    borrow::BorrowMut,
    boxed::Box,
    iter, mem,
    rand::{CryptoRng, RngCore},
    vec,
    vec::Vec,
    One, Zero,
};
use merlin::Transcript;

use super::{
    ConstraintSystem, LinearCombination, R1CSProof, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};

use crate::errors::R1CSError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::transcript::TranscriptProtocol;

/// A [`ConstraintSystem`] implementation for use by the verifier.
///
/// The verifier adds high-level variable commitments to the transcript,
/// allocates low-level variables and creates constraints in terms of these
/// high-level variables and low-level variables.
///
/// When all constraints are added, the verifying code calls `verify`
/// which consumes the `Verifier` instance, samples random challenges
/// that instantiate the randomized constraints, and verifies the proof.
pub struct Verifier<G: AffineRepr, T: BorrowMut<Transcript>> {
    transcript: T,
    constraints: Vec<LinearCombination<G::ScalarField>>,

    /// Records the number of low-level variables allocated in the
    /// constraint system.
    ///
    /// Because the `VerifierCS` only keeps the constraints
    /// themselves, it doesn't record the assignments (they're all
    /// `Missing`), so the `num_vars` isn't kept implicitly in the
    /// variable assignments.
    num_vars: usize,
    V: Vec<G>,

    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    /// After that, the option will flip to None and additional calls to `randomize_constraints`
    /// will invoke closures immediately.
    deferred_constraints: Vec<Box<dyn Fn(&mut RandomizingVerifier<G, T>) -> Result<(), R1CSError>>>,

    /// Index of a pending multiplier that's not fully assigned yet.
    pending_multiplier: Option<usize>,
}

/// Verifier in the randomizing phase.
///
/// Note: this type is exported because it is used to specify the associated type
/// in the public impl of a trait `ConstraintSystem`, which boils down to allowing compiler to
/// monomorphize the closures for the proving and verifying code.
/// However, this type cannot be instantiated by the user and therefore can only be used within
/// the callback provided to `specify_randomized_constraints`.
pub struct RandomizingVerifier<G: AffineRepr, T: BorrowMut<Transcript>> {
    verifier: Verifier<G, T>,
}

impl<T: BorrowMut<Transcript>, G: AffineRepr> ConstraintSystem<G::ScalarField> for Verifier<G, T> {
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
        let var = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        // Constrain l,r,o:
        left.terms.push((l_var, -G::ScalarField::one()));
        right.terms.push((r_var, -G::ScalarField::one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(
        &mut self,
        _: Option<G::ScalarField>,
    ) -> Result<Variable<G::ScalarField>, R1CSError> {
        match self.pending_multiplier {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending_multiplier = Some(i);
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        _: Option<(G::ScalarField, G::ScalarField)>,
    ) -> Result<
        (
            Variable<G::ScalarField>,
            Variable<G::ScalarField>,
            Variable<G::ScalarField>,
        ),
        R1CSError,
    > {
        let var = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        Ok((l_var, r_var, o_var))
    }

    fn multipliers_len(&self) -> usize {
        self.num_vars
    }

    fn constrain(&mut self, lc: LinearCombination<G::ScalarField>) {
        // TODO: check that the linear combinations are valid
        // (e.g. that variables are valid, that the linear combination
        // evals to 0 for prover, etc).
        self.constraints.push(lc);
    }
}

impl<T: BorrowMut<Transcript>, G: AffineRepr> RandomizableConstraintSystem<G::ScalarField>
    for Verifier<G, T>
{
    type RandomizedCS = RandomizingVerifier<G, T>;

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }
}

impl<T: BorrowMut<Transcript>, G: AffineRepr> ConstraintSystem<G::ScalarField>
    for RandomizingVerifier<G, T>
{
    fn transcript(&mut self) -> &mut Transcript {
        self.verifier.transcript.borrow_mut()
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
        self.verifier.multiply(left, right)
    }

    fn allocate(
        &mut self,
        assignment: Option<G::ScalarField>,
    ) -> Result<Variable<G::ScalarField>, R1CSError> {
        self.verifier.allocate(assignment)
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
        self.verifier.allocate_multiplier(input_assignments)
    }

    fn multipliers_len(&self) -> usize {
        self.verifier.multipliers_len()
    }

    fn constrain(&mut self, lc: LinearCombination<G::ScalarField>) {
        self.verifier.constrain(lc)
    }
}

impl<T: BorrowMut<Transcript>, G: AffineRepr> RandomizedConstraintSystem<G::ScalarField>
    for RandomizingVerifier<G, T>
{
    fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
        <Transcript as TranscriptProtocol<G>>::challenge_scalar(
            self.verifier.transcript.borrow_mut(),
            label,
        )
    }
}

impl<G: AffineRepr, T: BorrowMut<Transcript>> Verifier<G, T> {
    /// Construct an empty constraint system with specified external
    /// input variables.
    ///
    /// # Inputs
    ///
    /// The `transcript` parameter is a Merlin proof transcript.  The
    /// `VerifierCS` holds onto the `&mut Transcript` until it consumes
    /// itself during [`VerifierCS::verify`], releasing its borrow of the
    /// transcript.  This ensures that the transcript cannot be
    /// altered except by the `VerifierCS` before proving is complete.
    ///
    /// The `commitments` parameter is a list of Pedersen commitments
    /// to the external variables for the constraint system.  All
    /// external variables must be passed up-front, so that challenges
    /// produced by [`ConstraintSystem::challenge_scalar`] are bound
    /// to the external variables.
    ///
    /// # Returns
    ///
    /// Returns a tuple `(cs, vars)`.
    ///
    /// The first element is the newly constructed constraint system.
    ///
    /// The second element is a list of [`Variable`]s corresponding to
    /// the external inputs, which can be used to form constraints.
    pub fn new(mut transcript: T) -> Self {
        <Transcript as TranscriptProtocol<G>>::r1cs_domain_sep(transcript.borrow_mut());

        Verifier {
            transcript,
            num_vars: 0,
            V: Vec::new(),
            constraints: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Creates commitment to a high-level variable and adds it to the transcript.
    ///
    /// # Inputs
    ///
    /// The `commitment` parameter is a Pedersen commitment
    /// to the external variable for the constraint system.  All
    /// external variables must be passed up-front, so that challenges
    /// produced by [`ConstraintSystem::challenge_scalar`] are bound
    /// to the external variables.
    ///
    /// # Returns
    ///
    /// Returns a pair of a Pedersen commitment (as a compressed Ristretto point),
    /// and a [`Variable`] corresponding to it, which can be used to form constraints.
    pub fn commit(&mut self, commitment: G) -> Variable<G::ScalarField> {
        let i = self.V.len();
        self.V.push(commitment);

        // Add the commitment to the transcript.
        self.transcript.borrow_mut().append_point(b"V", &commitment);

        Variable::Committed(i)
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV, wc)
    /// ```
    /// where `w{L,R,O}` is \\( z \cdot z^Q \cdot W_{L,R,O} \\).
    ///
    /// This has the same logic as `ProverCS::flattened_constraints()`
    /// but also computes the constant terms (which the prover skips
    /// because they're not needed to construct the proof).
    fn flattened_constraints(
        &mut self,
        z: &G::ScalarField,
    ) -> (
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        Vec<G::ScalarField>,
        G::ScalarField,
    ) {
        let n = self.num_vars;
        let m = self.V.len();

        let mut wL = vec![G::ScalarField::zero(); n];
        let mut wR = vec![G::ScalarField::zero(); n];
        let mut wO = vec![G::ScalarField::zero(); n];
        let mut wV = vec![G::ScalarField::zero(); m];
        let mut wc = G::ScalarField::zero();

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
                        wc -= exp_z * coeff;
                    }
                    _ => {}
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV, wc)
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
            let mut wrapped_self = RandomizingVerifier { verifier: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.verifier)
        }
    }

    // Get scalars for single multiexponentiation verification
    // Order is
    // pc_gens.B
    // pc_gens.B_blinding
    // gens.G_vec
    // gens.H_vec
    // proof.A_I1
    // proof.A_O1
    // proof.S1
    // proof.A_I2
    // proof.A_O2
    // proof.S2
    // self.V
    // T_1, T3, T4, T5, T6
    // proof.ipp_proof.L_vec
    // proof.ipp_proof.R_vec
    pub(super) fn verification_scalars(
        mut self,
        proof: &R1CSProof<G>,
        bp_gens: &BulletproofGens<G>,
    ) -> Result<(Self, Vec<G::ScalarField>), R1CSError> {
        // Commit a length _suffix_ for the number of high-level variables.
        // We cannot do this in advance because user can commit variables one-by-one,
        // but this suffix provides safe disambiguation because each variable
        // is prefixed with a separate label.
        let transcript = self.transcript.borrow_mut();
        transcript.append_u64(b"m", self.V.len() as u64);

        let n1 = self.num_vars;
        transcript.validate_and_append_point(b"A_I1", &proof.A_I1)?;
        transcript.validate_and_append_point(b"A_O1", &proof.A_O1)?;
        transcript.validate_and_append_point(b"S1", &proof.S1)?;

        // Process the remaining constraints.
        self = self.create_randomized_constraints()?;

        let transcript = self.transcript.borrow_mut();

        // If the number of multiplications is not 0 or a power of 2, then pad the circuit.
        let n = self.num_vars;
        let n2 = n - n1;
        let padded_n = self.num_vars.next_power_of_two();
        let pad = padded_n - n;

        use crate::inner_product_proof::inner_product;
        use crate::util;

        if bp_gens.gens_capacity < padded_n {
            return Err(R1CSError::InvalidGeneratorsLength);
        }

        // These points are the identity in the 1-phase unrandomized case.
        transcript.append_point(b"A_I2", &proof.A_I2);
        transcript.append_point(b"A_O2", &proof.A_O2);
        transcript.append_point(b"S2", &proof.S2);

        let y: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"y");
        let z = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"z");

        transcript.validate_and_append_point(b"T_1", &proof.T_1)?;
        transcript.validate_and_append_point(b"T_3", &proof.T_3)?;
        transcript.validate_and_append_point(b"T_4", &proof.T_4)?;
        transcript.validate_and_append_point(b"T_5", &proof.T_5)?;
        transcript.validate_and_append_point(b"T_6", &proof.T_6)?;

        let u = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"u");
        let x = <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"x");

        <Transcript as TranscriptProtocol<G>>::append_scalar(transcript, b"t_x", &proof.t_x);
        <Transcript as TranscriptProtocol<G>>::append_scalar(
            transcript,
            b"t_x_blinding",
            &proof.t_x_blinding,
        );
        <Transcript as TranscriptProtocol<G>>::append_scalar(
            transcript,
            b"e_blinding",
            &proof.e_blinding,
        );

        let w: G::ScalarField =
            <Transcript as TranscriptProtocol<G>>::challenge_scalar(transcript, b"w");

        let (wL, wR, wO, wV, wc) = self.flattened_constraints(&z);

        // Get IPP variables
        let (u_sq, u_inv_sq, s) = proof
            .ipp_proof
            .verification_scalars(padded_n, self.transcript.borrow_mut())
            .map_err(|_| R1CSError::VerificationError)?;

        let a = proof.ipp_proof.a;
        let b = proof.ipp_proof.b;

        let y_inv = y.inverse().unwrap();
        let y_inv_vec = util::exp_iter::<G>(y_inv)
            .take(padded_n)
            .collect::<Vec<G::ScalarField>>();
        let yneg_wR = wR
            .into_iter()
            .zip(y_inv_vec.iter())
            .map(|(wRi, exp_y_inv)| wRi * exp_y_inv)
            .chain(iter::repeat(G::ScalarField::zero()).take(pad))
            .collect::<Vec<G::ScalarField>>();

        let delta = inner_product(&yneg_wR[0..n], &wL);

        let u_for_g = iter::repeat(G::ScalarField::one())
            .take(n1)
            .chain(iter::repeat(u).take(n2 + pad));
        let u_for_h = u_for_g.clone();

        // define parameters for P check
        let g_scalars: Vec<_> = yneg_wR
            .iter()
            .zip(u_for_g)
            .zip(s.iter().take(padded_n))
            .map(|((yneg_wRi, u_or_1), s_i)| u_or_1 * (x * yneg_wRi - a * s_i))
            .collect();

        let h_scalars: Vec<_> = y_inv_vec
            .iter()
            .zip(u_for_h)
            .zip(s.iter().rev().take(padded_n))
            .zip(
                wL.into_iter()
                    .chain(iter::repeat(G::ScalarField::zero()).take(pad)),
            )
            .zip(
                wO.into_iter()
                    .chain(iter::repeat(G::ScalarField::zero()).take(pad)),
            )
            .map(|((((y_inv_i, u_or_1), s_i_inv), wLi), wOi)| {
                u_or_1 * (*y_inv_i * (x * wLi + wOi - b * s_i_inv) - G::ScalarField::one())
            })
            .collect();

        let r: G::ScalarField = <Transcript as TranscriptProtocol<G>>::challenge_scalar(
            &mut self.transcript.borrow_mut().clone(),
            b"r",
        );

        let xx = x * x;
        let rxx = r * xx;
        let xxx = x * xx;

        // group the T_scalars and T_points together
        let T_scalars = [r * x, rxx * x, rxx * xx, rxx * xxx, rxx * xx * xx];

        let mut scalars: Vec<G::ScalarField> = vec![];
        scalars.push(w * (proof.t_x - a * b) + r * (xx * (wc + delta) - proof.t_x));
        scalars.push(-proof.e_blinding - r * proof.t_x_blinding);
        scalars.extend_from_slice(&g_scalars);
        scalars.extend_from_slice(&h_scalars);
        scalars.extend_from_slice(&[x, xx, xxx, u * x, u * xx, u * xxx]);
        for wVi in wV.iter() {
            scalars.push(*wVi * rxx);
        }
        scalars.extend_from_slice(&T_scalars);
        scalars.extend_from_slice(&u_sq);
        scalars.extend_from_slice(&u_inv_sq);
        Ok((self, scalars))
    }

    /// Consume this `VerifierCS` and attempt to verify the supplied `proof`.
    /// The `pc_gens` and `bp_gens` are generators for Pedersen commitments and
    /// Bulletproofs vector commitments, respectively.  The
    /// [`BulletproofGens`] should have `gens_capacity` greater than
    /// the number of multiplication constraints that will eventually
    /// be added into the constraint system.
    pub fn verify(
        self,
        proof: &R1CSProof<G>,
        pc_gens: &PedersenGens<G>,
        bp_gens: &BulletproofGens<G>,
    ) -> Result<(), R1CSError> {
        self.verify_and_return_transcript(proof, pc_gens, bp_gens)
            .map(|_| ())
    }
    /// Same as `verify`, but also returns the transcript back to the user.
    pub fn verify_and_return_transcript(
        mut self,
        proof: &R1CSProof<G>,
        pc_gens: &PedersenGens<G>,
        bp_gens: &BulletproofGens<G>,
    ) -> Result<T, R1CSError> {
        let (verifier, scalars) = self.verification_scalars(proof, bp_gens)?;
        self = verifier;
        let T_points = [proof.T_1, proof.T_3, proof.T_4, proof.T_5, proof.T_6];

        // We are performing a single-party circuit proof, so party index is 0.
        let gens = bp_gens.share(0);

        let padded_n = self.num_vars.next_power_of_two();

        let mega_check = G::Group::msm(
            &iter::once(&pc_gens.B)
                .chain(iter::once(&pc_gens.B_blinding))
                .chain(gens.G(padded_n))
                .chain(gens.H(padded_n))
                .chain(iter::once(&proof.A_I1))
                .chain(iter::once(&proof.A_O1))
                .chain(iter::once(&proof.S1))
                .chain(iter::once(&proof.A_I2))
                .chain(iter::once(&proof.A_O2))
                .chain(iter::once(&proof.S2))
                .chain(self.V.iter())
                .chain(T_points.iter())
                .chain(proof.ipp_proof.L_vec.iter())
                .chain(proof.ipp_proof.R_vec.iter())
                .cloned()
                .collect::<Vec<G>>(),
            &scalars,
        )
        .unwrap();

        if !mega_check.is_zero() {
            return Err(R1CSError::VerificationError);
        }

        Ok(self.transcript)
    }
}

/// Batch verification of R1CS proofs
pub fn batch_verify<'a, G: AffineRepr, I, R: CryptoRng + RngCore>(
    prng: &mut R,
    instances: I,
    pc_gens: &PedersenGens<G>,
    bp_gens: &BulletproofGens<G>,
) -> Result<(), R1CSError>
where
    I: IntoIterator<Item = (Verifier<G, &'a mut Transcript>, &'a R1CSProof<G>)>,
{
    let mut max_n_padded = 0;
    let mut verifiers: Vec<Verifier<G, _>> = vec![];
    let mut proofs: Vec<&R1CSProof<G>> = vec![];
    let mut verification_scalars = vec![];
    for (verifier, proof) in instances.into_iter() {
        // verification_scalars method is mutable, need to run before obtaining verifier.num_vars
        let (verifier, scalars) = verifier.verification_scalars(proof, bp_gens)?;
        let n = verifier.num_vars.next_power_of_two();
        if n > max_n_padded {
            max_n_padded = n;
        }
        verification_scalars.push(scalars);
        verifiers.push(verifier);
        proofs.push(proof);
    }
    let mut all_scalars = vec![];
    let mut all_elems = vec![];

    for _ in 0..(2 * max_n_padded + 2) {
        all_scalars.push(G::ScalarField::zero());
    }
    all_elems.push(pc_gens.B);
    all_elems.push(pc_gens.B_blinding);
    let gens = bp_gens.share(0);
    for G in gens.G(max_n_padded) {
        all_elems.push(*G);
    }
    for H in gens.H(max_n_padded) {
        all_elems.push(*H);
    }

    for ((verifier, proof), scalars) in verifiers
        .into_iter()
        .zip(proofs.iter())
        .zip(verification_scalars.iter())
    {
        let alpha = G::ScalarField::rand(prng);
        let scaled_scalars: Vec<G::ScalarField> = scalars.iter().map(|s| alpha * s).collect();
        let padded_n = verifier.num_vars.next_power_of_two();
        all_scalars[0] += scaled_scalars[0]; // B
        all_scalars[1] += scaled_scalars[1]; // B_blinding
                                             // g values
        for (i, s) in scaled_scalars[2..2 + padded_n].iter().enumerate() {
            all_scalars[i + 2] += s;
        }
        // h values
        for (i, s) in scaled_scalars[2 + padded_n..2 + 2 * padded_n]
            .iter()
            .enumerate()
        {
            all_scalars[2 + max_n_padded + i] += *s;
        }

        for s in &scaled_scalars[2 + 2 * padded_n..] {
            all_scalars.push(*s);
        }
        all_elems.push(proof.A_I1);
        all_elems.push(proof.A_O1);
        all_elems.push(proof.S1);
        all_elems.push(proof.A_I2);
        all_elems.push(proof.A_O2);
        all_elems.push(proof.S2);
        all_elems.extend_from_slice(verifier.V.as_slice());
        all_elems.push(proof.T_1);
        all_elems.push(proof.T_3);
        all_elems.push(proof.T_4);
        all_elems.push(proof.T_5);
        all_elems.push(proof.T_6);
        all_elems.extend_from_slice(&proof.ipp_proof.L_vec);
        all_elems.extend_from_slice(&proof.ipp_proof.R_vec);
    }

    let multi_exp = G::Group::msm(&all_elems, &all_scalars).unwrap();
    if !multi_exp.is_zero() {
        Err(R1CSError::VerificationError)
    } else {
        Ok(())
    }
}
