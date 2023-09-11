use ark_ff::fields::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "115792089237316195423570985008687907853269984665640564039457584007908834671663"]
#[generator = "1"]

pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;
