#![forbid(unsafe_code)]

//! This library implements the secq256k1 curve.
//! Source: <https://moderncrypto.org/mail-archive/curves/2018/000992.html>
//!
//! Curve information:
//! * Base field: q =
//!   115792089237316195423570985008687907852837564279074904382605163141518161494337
//! * Scalar field: r =
//!   115792089237316195423570985008687907853269984665640564039457584007908834671663
//! * Curve equation: y^2 = x^3 + 7

#[cfg(feature = "r1cs")]
pub mod constraints;
mod curves;
mod fields;

pub use curves::*;
pub use fields::*;
