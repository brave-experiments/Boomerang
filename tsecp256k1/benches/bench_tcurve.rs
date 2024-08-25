use ark_secp256k1::Config as secp256k1conf;
use boomerang_macros::bench_tcurve_make_all;
use tsecp256k1::Config;
type OtherProjectiveType = sw::Projective<secp256k1conf>;
bench_tcurve_make_all!(Config, "tsecp256k1", OtherProjectiveType);
