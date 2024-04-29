# Bulletproofs over the secq256k1 curve

This repo builds over [Bulletproofs][bp_website] but replaces the 
Ristretto group with another group over the secq256k1 curve.

An important property of the secq256k1 curve is that it can embed secp256k1. A severe
limitation, as a result, is that its scalar field does not have a lot of 
2-arity, and therefore preventing a large class of protocols based on FFT
to run on the native field.

There are only a few solutions we know today to circumvent this limitation: 
Bulletproofs, Gemini, and Orion. For this library, we use Bulletproofs.

## Original About

This is a research project sponsored by [Interstellar][interstellar],
developed by Henry de Valence, Cathie Yun, and Oleg Andreev.

[bp_website]: https://crypto.stanford.edu/bulletproofs/
[ristretto]: https://ristretto.group
[doc_merlin]: https://doc.dalek.rs/merlin/index.html
[doc_external]: https://doc.dalek.rs/bulletproofs/index.html
[doc_internal]: https://doc-internal.dalek.rs/bulletproofs/index.html
[bp_notes]: https://doc-internal.dalek.rs/bulletproofs/notes/index.html
[rp_notes]: https://doc-internal.dalek.rs/bulletproofs/range_proof/index.html
[ipp_notes]: https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html
[agg_notes]: https://doc-internal.dalek.rs/bulletproofs/notes/index.html#aggregated-range-proof
[criterion]: https://github.com/japaric/criterion.rs
[session_type_blog]: https://blog.chain.com/bulletproof-multi-party-computation-in-rust-with-session-types-b3da6e928d5d
[curve25519_dalek]: https://doc.dalek.rs/curve25519_dalek/index.html
[parallel_edwards]: https://medium.com/@hdevalence/accelerating-edwards-curve-arithmetic-with-parallel-formulas-ac12cf5015be
[gh_repo]: https://github.com/dalek-cryptography/bulletproofs/
[gh_milestones]: https://github.com/dalek-cryptography/bulletproofs/milestones
[interstellar]: https://interstellar.com/
