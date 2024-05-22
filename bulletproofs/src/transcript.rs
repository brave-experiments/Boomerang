//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.

use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::SeedableRng, vec::Vec, UniformRand};
use merlin::Transcript;
use rand_chacha::ChaChaRng;

use crate::errors::ProofError;

pub trait TranscriptProtocol<G: AffineRepr> {
    /// Append a domain separator for an `n`-bit, `m`-party range proof.
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64);

    /// Append a domain separator for a length-`n` inner product proof.
    fn innerproduct_domain_sep(&mut self, n: u64);

    /// Append a domain separator for a constraint system.
    fn r1cs_domain_sep(&mut self);

    /// Commit a domain separator for a CS without randomized constraints.
    fn r1cs_1phase_domain_sep(&mut self);

    /// Commit a domain separator for a CS with randomized constraints.
    fn r1cs_2phase_domain_sep(&mut self);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField);

    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &G);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G,
    ) -> Result<(), ProofError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField;
}

impl<G: AffineRepr> TranscriptProtocol<G> for Transcript {
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64) {
        self.append_message(b"dom-sep", b"rangeproof v1");
        self.append_u64(b"n", n);
        self.append_u64(b"m", m);
    }

    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ipp v1");
        self.append_u64(b"n", n);
    }

    fn r1cs_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs v1");
    }

    fn r1cs_1phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-1phase");
    }

    fn r1cs_2phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-2phase");
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField) {
        let mut bytes = Vec::new();
        scalar.serialize_uncompressed(&mut bytes).unwrap();
        self.append_message(label, &bytes);
    }

    fn append_point(&mut self, label: &'static [u8], point: &G) {
        let mut bytes = Vec::new();
        point.serialize_uncompressed(&mut bytes).unwrap();
        self.append_message(label, &bytes);
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G,
    ) -> Result<(), ProofError> {
        if point.is_zero() {
            Err(ProofError::VerificationError)
        } else {
            let mut bytes = Vec::new();
            point.serialize_uncompressed(&mut bytes).unwrap();
            self.append_message(label, &bytes);
            Ok(())
        }
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
        let mut buf = [0u8; 32];
        self.challenge_bytes(label, &mut buf);

        let mut prng = ChaChaRng::from_seed(buf);
        G::ScalarField::rand(&mut prng)
    }
}
