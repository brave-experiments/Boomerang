#![cfg_attr(not(feature = "std"), no_std)]

mod util;

mod errors;
mod generators;
mod inner_product_proof;
mod linear_proof;
mod range_proof;
mod transcript;

pub use crate::errors::ProofError;
pub use crate::generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use crate::inner_product_proof::{inner_product, InnerProductProof};
pub use crate::linear_proof::LinearProof;
pub use crate::range_proof::RangeProof;

#[cfg(feature = "yoloproofs")]
pub mod r1cs;
