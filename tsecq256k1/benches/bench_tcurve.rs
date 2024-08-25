use ark_secq256k1::Config as secq256k1conf;
use boomerang_macros::bench_tcurve_make_all;
use tsecq256k1::Config;
type OtherProjectiveType = sw::Projective<secq256k1conf>;
bench_tcurve_make_all!(Config, "tsecq256k1", OtherProjectiveType);
