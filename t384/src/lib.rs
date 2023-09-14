#![deny(nonstandard_style)]
#![forbid(unsafe_code)]

//! This library implements the 384-bit prime order curve used inside ZKAttest.
//!
//! Curve infomration:
//! * Base field:   q = 0xfffffffffffffffffffffffffffffffffffffffffffffffeaf5f689f8669fb41b08d5f5edffd26599c434bbd978917c5
//! * Scalar field: r = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
//!
//! Note that by "base field" we mean "the characteristic of the underlying finite field" and by "scalar field" we mean
//! "the order of the curve".
//!
//! * Curve equation: y^2 = x^3 + a_4*x + a_6, where
//!   a_4 = 0x821dfdc940e7f074ac481f8b2870c48962cce56abd72dfc42813a944cea15df78dc0a2d97fbf031ed26c9076826940ba
//!   a_6 = 0x9b5b584b655fdcb087d37f8c4fee893c0499223db5e004c674ea0dee48a4ec0c9e9f684099f2a51c62a2cce400cb1e4b

#[cfg(feature = "r1cs")]
pub mod constraints;
mod curves;
mod fields;

pub use curves::*;
pub use fields::*;
