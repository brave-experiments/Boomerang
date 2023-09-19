use t384::Config;
use cdls_macros::bench_tcurve_make_all;
use ark_secp384r1::Config as secp384r1conf;
type OtherProjectiveType = sw::Projective<secp384r1conf>;
bench_tcurve_make_all!(Config, "t384", OtherProjectiveType);
