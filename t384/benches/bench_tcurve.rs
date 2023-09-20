use ark_secp384r1::Config as secp384r1conf;
use cdls_macros::bench_tcurve_make_all;
use t384::Config;
type OtherProjectiveType = sw::Projective<secp384r1conf>;
bench_tcurve_make_all!(Config, "t384", OtherProjectiveType);
