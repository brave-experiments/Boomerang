//! The `messages` module contains the API for the messages passed between the parties and the dealer
//! in an aggregated multiparty computation protocol.
//!
//! For more explanation of how the `dealer`, `party`, and `messages` modules orchestrate the protocol execution, see
//! [the API for the aggregated multiparty computation protocol](../aggregation/index.html#api-for-the-aggregated-multiparty-computation-protocol).

use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_std::{
    iter,
    ops::{Add, Mul, Neg, Sub},
    rand::{CryptoRng, RngCore},
    vec::Vec,
    One, Zero,
};

use crate::generators::{BulletproofGens, PedersenGens};

/// A commitment to the bits of a party's value.
#[derive(Copy, Clone, Debug)]
pub struct BitCommitment<G: AffineRepr> {
    pub(super) V_j: G,
    pub(super) A_j: G,
    pub(super) S_j: G,
}

/// Challenge values derived from all parties' [`BitCommitment`]s.
#[derive(Copy, Clone, Debug)]
pub struct BitChallenge<G: AffineRepr> {
    pub(super) y: G::ScalarField,
    pub(super) z: G::ScalarField,
}

/// A commitment to a party's polynomial coefficents.
#[derive(Copy, Clone, Debug)]
pub struct PolyCommitment<G: AffineRepr> {
    pub(super) T_1_j: G,
    pub(super) T_2_j: G,
}

/// Challenge values derived from all parties' [`PolyCommitment`]s.
#[derive(Copy, Clone, Debug)]
pub struct PolyChallenge<G: AffineRepr> {
    pub(super) x: G::ScalarField,
}

/// A party's proof share, ready for aggregation into the final
/// [`RangeProof`](::RangeProof).
#[derive(Clone, Debug)]
pub struct ProofShare<G: AffineRepr> {
    pub(super) t_x: G::ScalarField,
    pub(super) t_x_blinding: G::ScalarField,
    pub(super) e_blinding: G::ScalarField,
    pub(super) l_vec: Vec<G::ScalarField>,
    pub(super) r_vec: Vec<G::ScalarField>,
}

impl<G: AffineRepr> ProofShare<G> {
    /// Checks consistency of all sizes in the proof share and returns the size of the l/r vector.
    pub(super) fn check_size(
        &self,
        expected_n: usize,
        bp_gens: &BulletproofGens<G>,
        j: usize,
    ) -> Result<(), ()> {
        if self.l_vec.len() != expected_n {
            return Err(());
        }

        if self.r_vec.len() != expected_n {
            return Err(());
        }

        if expected_n > bp_gens.gens_capacity {
            return Err(());
        }

        if j >= bp_gens.party_capacity {
            return Err(());
        }

        Ok(())
    }

    /// Audit an individual proof share to determine whether it is
    /// malformed.
    pub(super) fn audit_share(
        &self,
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        j: usize,
        bit_commitment: &BitCommitment<G>,
        bit_challenge: &BitChallenge<G>,
        poly_commitment: &PolyCommitment<G>,
        poly_challenge: &PolyChallenge<G>,
    ) -> Result<(), ()> {
        use crate::inner_product_proof::inner_product;
        use crate::util;

        let n = self.l_vec.len();

        self.check_size(n, bp_gens, j)?;

        let (y, z) = (&bit_challenge.y, &bit_challenge.z);
        let x = &poly_challenge.x;

        // Precompute some variables
        let zz = *z * z;
        let minus_z = z.neg();
        let z_j = z.pow(&[j as u64]); // z^j
        let y_jn = y.pow(&[(j * n) as u64]); // y^(j*n)
        let y_jn_inv = y_jn.inverse().unwrap(); // y^(-j*n)
        let y_inv = y.inverse().unwrap(); // y^(-1)

        if self.t_x != inner_product(&self.l_vec, &self.r_vec) {
            return Err(());
        }

        let g = self.l_vec.iter().map(|l_i| minus_z - l_i);
        let h = self
            .r_vec
            .iter()
            .zip(util::exp_iter::<G>(G::ScalarField::from(2u64)))
            .zip(util::exp_iter::<G>(y_inv))
            .map(|((r_i, exp_2), exp_y_inv)| {
                *z + exp_y_inv * y_jn_inv * r_i.neg() + exp_y_inv * y_jn_inv * (zz * z_j * exp_2)
            });

        let P_check = G::Group::msm(
            &iter::once(&bit_commitment.A_j)
                .chain(iter::once(&bit_commitment.S_j))
                .chain(iter::once(&pc_gens.B_blinding))
                .chain(bp_gens.share(j).G(n))
                .chain(bp_gens.share(j).H(n))
                .map(|f| f.clone())
                .collect::<Vec<G>>(),
            &iter::once(G::ScalarField::one())
                .chain(iter::once(*x))
                .chain(iter::once(self.e_blinding.neg()))
                .chain(g)
                .chain(h)
                .map(|f| f) // TODO: check
                .collect::<Vec<G::ScalarField>>(), //TODO: check
        );
        if !P_check.unwrap().is_zero() {
            return Err(());
        }

        let sum_of_powers_y = util::sum_of_powers::<G>(&y, n);
        let sum_of_powers_2 = util::sum_of_powers::<G>(&G::ScalarField::from(2u64), n);
        let delta = (*z - zz) * sum_of_powers_y * y_jn - *z * zz * sum_of_powers_2 * z_j;
        let t_check = G::Group::msm(
            &iter::once(&bit_commitment.V_j)
                .chain(iter::once(&poly_commitment.T_1_j))
                .chain(iter::once(&poly_commitment.T_2_j))
                .chain(iter::once(&pc_gens.B))
                .chain(iter::once(&pc_gens.B_blinding))
                .map(|f| f.clone())
                .collect::<Vec<G>>(),
            &iter::once(zz * z_j)
                .chain(iter::once(*x))
                .chain(iter::once(*x * x))
                .chain(iter::once(delta - &self.t_x))
                .chain(iter::once(self.t_x_blinding.neg()))
                .map(|f| f)
                .collect::<Vec<G::ScalarField>>(), //TODO: check
        );

        if t_check.unwrap().is_zero() {
            Ok(())
        } else {
            Err(())
        }
    }
}
