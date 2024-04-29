//! Errors related to proving and verifying proofs.

use ark_serialize::SerializationError;
use ark_std::{
    fmt,
    string::{String, ToString},
    vec::Vec,
};

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Eq, PartialEq)]
pub enum ProofError {
    /// This error occurs when a proof failed to verify.
    VerificationError,
    /// This error occurs when the proof encoding is malformed.
    FormatError,
    /// This error occurs during proving if the number of blinding
    /// factors does not match the number of values.
    WrongNumBlindingFactors,
    /// This error occurs when attempting to create a proof with
    /// bitsize other than \\(8\\), \\(16\\), \\(32\\), or \\(64\\).
    InvalidBitsize,
    /// This error occurs when attempting to create an aggregated
    /// proof with non-power-of-two aggregation size.
    InvalidAggregation,
    /// This error occurs when there are insufficient generators for the proof.
    InvalidGeneratorsLength,
    /// This error results from an internal error during proving.
    ///
    /// The single-party prover is implemented by performing
    /// multiparty computation with ourselves.  However, because the
    /// MPC protocol is not exposed by the single-party API, we
    /// consider its errors to be internal errors.
    ProvingError(MPCError),
    /// This error occurs if serialization fails
    SerializationError(String),
}

impl fmt::Debug for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::VerificationError => write!(f, "Proof verification failed."),
            ProofError::FormatError => write!(f, "Proof data could not be parsed."),
            ProofError::WrongNumBlindingFactors => {
                write!(f, "Wrong number of blinding factors supplied.")
            }
            ProofError::InvalidBitsize => write!(f, "Invalid bitsize, must have n = 8,16,32,64."),
            ProofError::InvalidAggregation => {
                write!(f, "Invalid aggregation size, m must be a power of 2.")
            }
            ProofError::InvalidGeneratorsLength => {
                write!(f, "Invalid generators size, too few generators for proof")
            }
            ProofError::ProvingError(e) => {
                write!(f, "Internal error during proof creation: {:?}", e)
            }
            ProofError::SerializationError(e) => {
                write!(f, "Serialization error: {}", e)
            }
        }
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<MPCError> for ProofError {
    fn from(e: MPCError) -> ProofError {
        match e {
            MPCError::InvalidBitsize => ProofError::InvalidBitsize,
            MPCError::InvalidAggregation => ProofError::InvalidAggregation,
            MPCError::InvalidGeneratorsLength => ProofError::InvalidGeneratorsLength,
            _ => ProofError::ProvingError(e),
        }
    }
}

/// Represents an error during the multiparty computation protocol for
/// proof aggregation.
///
/// This is a separate type from the `ProofError` to allow a layered
/// API: although the MPC protocol is used internally for single-party
/// proving, its API should not expose the complexity of the MPC
/// protocol.
#[derive(Clone, Eq, PartialEq)]
pub enum MPCError {
    /// This error occurs when the dealer gives a zero challenge,
    /// which would annihilate the blinding factors.
    MaliciousDealer,
    /// This error occurs when attempting to create a proof with
    /// bitsize other than \\(8\\), \\(16\\), \\(32\\), or \\(64\\).
    InvalidBitsize,
    /// This error occurs when attempting to create an aggregated
    /// proof with non-power-of-two aggregation size.
    InvalidAggregation,
    /// This error occurs when there are insufficient generators for the proof.
    InvalidGeneratorsLength,
    /// This error occurs when the dealer is given the wrong number of
    /// value commitments.
    WrongNumBitCommitments,
    /// This error occurs when the dealer is given the wrong number of
    /// polynomial commitments.
    WrongNumPolyCommitments,
    /// This error occurs when the dealer is given the wrong number of
    /// proof shares.
    WrongNumProofShares,
    /// This error occurs when one or more parties submit malformed
    /// proof shares.
    MalformedProofShares {
        /// A vector with the indexes of the parties whose shares were malformed.
        bad_shares: Vec<usize>,
    },
}

impl fmt::Debug for MPCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MPCError::MaliciousDealer => write!(f, "Dealer gave a malicious challenge value."),
            MPCError::InvalidBitsize => write!(f, "Invalid bitsize, must have n = 8,16,32,64"),
            MPCError::InvalidAggregation => {
                write!(f, "Invalid aggregation size, m must be a power of 2")
            }
            MPCError::InvalidGeneratorsLength => {
                write!(f, "Invalid generators size, too few generators for proof")
            }
            MPCError::WrongNumBitCommitments => write!(f, "Wrong number of value commitments"),
            MPCError::WrongNumPolyCommitments => write!(f, "Wrong number of value commitments"),
            MPCError::WrongNumProofShares => write!(f, "Wrong number of proof shares"),
            MPCError::MalformedProofShares { bad_shares } => {
                write!(f, "Malformed proof shares from parties {:?}", bad_shares)
            }
        }
    }
}

impl fmt::Display for MPCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Represents an error during the proving or verifying of a constraint system.
///
/// XXX: should this be separate from a `ProofError`?
#[cfg(feature = "yoloproofs")]
#[derive(Clone, Eq, PartialEq)]
pub enum R1CSError {
    /// Occurs when there are insufficient generators for the proof.
    InvalidGeneratorsLength,
    /// This error occurs when the proof encoding is malformed.
    FormatError,
    /// Occurs when verification of an
    /// [`R1CSProof`](::r1cs::R1CSProof) fails.
    VerificationError,
    /// Occurs when trying to use a missing variable assignment.
    /// Used by gadgets that build the constraint system to signal that
    /// a variable assignment is not provided when the prover needs it.
    MissingAssignment,
    /// Occurs when a gadget receives an inconsistent input.
    GadgetError {
        /// The description of the reasons for the error.
        description: String,
    },
}

impl fmt::Debug for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            R1CSError::InvalidGeneratorsLength => {
                write!(f, "Invalid generators size, too few generators for proof")
            }
            R1CSError::FormatError => write!(f, "Proof data could not be parsed."),
            R1CSError::VerificationError => write!(f, "R1CSProof did not verify correctly."),
            R1CSError::MissingAssignment => write!(f, "Variable does not have a value assignment."),
            R1CSError::GadgetError { description } => write!(f, "Gadget error: {}", description),
        }
    }
}

impl fmt::Display for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "yoloproofs")]
impl From<ProofError> for R1CSError {
    fn from(e: ProofError) -> R1CSError {
        match e {
            ProofError::InvalidGeneratorsLength => R1CSError::InvalidGeneratorsLength,
            ProofError::FormatError => R1CSError::FormatError,
            ProofError::VerificationError => R1CSError::VerificationError,
            _ => panic!("unexpected error type in conversion"),
        }
    }
}

impl From<ark_std::io::Error> for ProofError {
    fn from(e: ark_std::io::Error) -> ProofError {
        ProofError::SerializationError(e.to_string())
    }
}

impl From<SerializationError> for ProofError {
    fn from(_: ark_serialize::SerializationError) -> ProofError {
        ProofError::FormatError
    }
}
