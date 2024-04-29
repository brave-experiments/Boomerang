#![allow(non_snake_case)]
//! Definition of the proof struct.

use crate::{errors::R1CSError, inner_product_proof::InnerProductProof, ProofError};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{io::Cursor, vec::Vec};

/// A proof of some statement specified by a
/// [`ConstraintSystem`](::r1cs::ConstraintSystem).
///
/// Statements are specified by writing gadget functions which add
/// constraints to a [`ConstraintSystem`](::r1cs::ConstraintSystem)
/// implementation.  To construct an [`R1CSProof`], a prover constructs
/// a [`ProverCS`](::r1cs::ProverCS), then passes it to gadget
/// functions to build the constraint system, then consumes the
/// constraint system using
/// [`ProverCS::prove`](::r1cs::ProverCS::prove) to produce an
/// [`R1CSProof`].  To verify an [`R1CSProof`], a verifier constructs a
/// [`VerifierCS`](::r1cs::VerifierCS), then passes it to the same
/// gadget functions to (re)build the constraint system, then consumes
/// the constraint system using
/// [`VerifierCS::verify`](::r1cs::VerifierCS::verify) to verify the
/// proof.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
#[allow(non_snake_case)]
pub struct R1CSProof<G: AffineRepr> {
    /// Commitment to the values of input wires in the first phase.
    pub(super) A_I1: G,
    /// Commitment to the values of output wires in the first phase.
    pub(super) A_O1: G,
    /// Commitment to the blinding factors in the first phase.
    pub(super) S1: G,
    /// Commitment to the values of input wires in the second phase.
    pub(super) A_I2: G,
    /// Commitment to the values of output wires in the second phase.
    pub(super) A_O2: G,
    /// Commitment to the blinding factors in the second phase.
    pub(super) S2: G,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    pub(super) T_1: G,
    /// Commitment to the \\(t_3\\) coefficient of \\( t(x) \\)
    pub(super) T_3: G,
    /// Commitment to the \\(t_4\\) coefficient of \\( t(x) \\)
    pub(super) T_4: G,
    /// Commitment to the \\(t_5\\) coefficient of \\( t(x) \\)
    pub(super) T_5: G,
    /// Commitment to the \\(t_6\\) coefficient of \\( t(x) \\)
    pub(super) T_6: G,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    pub(super) t_x: G::ScalarField,
    /// Blinding factor for the synthetic commitment to \\( t(x) \\)
    pub(super) t_x_blinding: G::ScalarField,
    /// Blinding factor for the synthetic commitment to the
    /// inner-product arguments
    pub(super) e_blinding: G::ScalarField,
    /// Proof data for the inner-product argument.
    pub(super) ipp_proof: InnerProductProof<G>,
}

impl<G: AffineRepr> R1CSProof<G> {
    /// Serializes the proof into a byte array of 1 version byte + \\((13 or 16) + 2k\\) 32-byte elements,
    /// where \\(k=\lceil \log_2(n) \rceil\\) and \\(n\\) is the number of multiplication gates.
    ///
    /// # Layout
    ///
    /// The layout of the r1cs proof encoding is:
    /// * 1 version byte indicating whether the proof contains second-phase commitments or not,
    /// * 8 or 11 compressed Ristretto points \\(A_{I1},A_{O1},S_1,(A_{I2},A_{O2},S_2),T_1,...,T_6\\)
    ///   (\\(A_{I2},A_{O2},S_2\\) are skipped if there were no multipliers added in the randomized phase),
    /// * three scalars \\(t_x, \tilde{t}_x, \tilde{e}\\),
    /// * \\(k\\) pairs of compressed Ristretto points \\(L_0,R_0\dots,L_{k-1},R_{k-1}\\),
    /// * two scalars \\(a, b\\).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut cursor = Cursor::new(Vec::new());
        self.serialize_compressed(&mut cursor)?;
        Ok(cursor.into_inner())
    }

    /// Deserializes the proof from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `R1CSProof`.
    pub fn from_bytes(slice: &[u8]) -> Result<R1CSProof<G>, R1CSError> {
        let mut cursor = Cursor::new(slice);
        let proof = R1CSProof::<G>::deserialize_compressed(&mut cursor);
        if proof.is_ok() {
            Ok(proof.unwrap())
        } else {
            Err(R1CSError::FormatError)
        }
    }
}
