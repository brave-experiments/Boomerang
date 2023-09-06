use ark_ff::fields::{Fp384, MontBackend, MontConfig};
#[derive(MontConfig)]
#[modulus = "39402006196394479212279040100143613805079739270465446667940039326625812510850684806287457257749692633059273959086021"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp384<MontBackend<FqConfig, 6>>;
