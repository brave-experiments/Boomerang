#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! This library implements the 256-bit prime order curve used inside ZKAttest.
//! Note: we use the values here from the ZKAttest implementation:
//!    https://github.com/cloudflare/zkp-ecdsa/blob/0af748d23b535a8fffebca34ab51abf37ef1ea13/src/curves/instances.ts#L34,
//! which are different from those that are given in the paper.
//!
//! Curve infomration:
//! * Base field:   q = 0xffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117 
//! * Scalar field: r = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
//!
//! Note that by "base field" we mean "the characteristic of the underlying finite field" and by "scalar field" we mean
//! "the order of the curve". 
//!
//! * Curve equation: y^2 = x^3 + a_4*x + a_6, where
//!   a_4 = -3
//!   a_6 = 0x5a6dd32df58708e64e97345cbe66600decd9d538a351bb3c30b4954925b1f02d
//!
//! Or, in decimal, a_4 = -3
//!                 a_6 = 81531206846337786915455327229510804132577517753388365729879493166393691077718

#[cfg(feature = "r1cs")]
pub mod constraints;
mod curves;
mod fields;

pub use curves::*;
pub use fields::*;
