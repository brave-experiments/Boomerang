use t256::Config;
use cdls_macros::bench_tcurve_make_all;
use ark_secp256r1::Config as secp256r1conf;
type OtherProjectiveType = sw::Projective<secp256r1conf>;
bench_tcurve_make_all!(Config, "t256", OtherProjectiveType);
