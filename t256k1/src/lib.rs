#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! This library implements a TCurve for SECP256k1.
//!
//! Curve infomration:
//! * Base field:   q = 0x1000000000000000000000000000000011225471b50b8dc249e5ff726d4163f21
//! * Scalar field: r = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
//!
//! Note that by "base field" we mean "the characteristic of the underlying finite field" and by "scalar field" we mean
//! "the order of the curve". 
//! 
//! Reconstructing the curve in Sage:
//!
//! sage> q = 0x1000000000000000000000000000000011225471b50b8dc249e5ff726d4163f21
//! sage> k = GF(q)
//! sage: a = 89379953207395194020409672220816588337067105588249253258410441773207003882916
//! sage: b = 89045740451045537684011562258967924075515675717646351873847622095823708405337
//! sage: E = EllipticCurve(k, (a, b))
//! sage: r = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
//! sage: E.order() == r
//! True
//!
//!
//! * Curve equation: y^2 = x^3 + a_4*x + a_6, where
//!   a_4 = 0xf312a28ec80129e2634af4a131a5d84e8618ff77a345b2c865ed11bdc25235e4
//!   a_6 = 0xe5822bbdf85f0656167a9288dd0bd81c3f76e105cc21bb604eb0f883b42e090e
//!
//! Or, in decimal, a_4 = 89379953207395194020409672220816588337067105588249253258410441773207003882916
//!                 a_6 = 89045740451045537684011562258967924075515675717646351873847622095823708405337

#[cfg(feature = "r1cs")]
pub mod constraints;
mod curves;
mod fields;

pub use curves::*;
pub use fields::*;

