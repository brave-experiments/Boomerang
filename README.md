# Boomerang

This is an implementation of "[Boomerang](https://arxiv.org/abs/2401.01353)", a novel decentralised privacy-preserving incentive protocol that leverages cryptographic black box
accumulators to securely store user interactions within incentive systems.
The protocol employs black-box accumulators, zero-knowledge proofs, the ACL signature scheme and Pedersen commitments for issuance, accumulation and redemption.
In this way, systems can transparently compute rewards for users, ensuring verifiability while  preserving their privacy.

## Quick Start

In order to build, run either:

    make

or

    cargo build

To test:

    cargo test --release

To benchmark:

    cargo bench

To see the the protocol in action, run the end2end example client and server
programs in separate terminals:
```sh
cargo run --bin server
```
and then
```sh
cargo run --bin client
```

These end2end examples are also run automatically after the unit tests
as part of `make test`.

## Components

The implementation is broken down into a number of crates handling
specific parts of the protocol, tests, and demonstration code.

- `boomerang`: Overall protocol implementation with separate representations for the client and server sides. It implements the issuance, collection and spend-verify sub-protocols.
- `pedersen`: Commitment scheme after **Pedersen,** “[Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing](https://doi.org/10.1007/3-540-46766-1_9).” *Advances in Cryptology* CRYPTO ’91, LNCS 576, pp. 129-140, 1992. Based on [code](https://github.com/brave-experiments/CDLS) from the [CDLS paper](https://eprint.iacr.org/2023/1595).
- `acl`: [Anonymous Credentials Light](https://eprint.iacr.org/2012/298) blind signature system after **Baldimtsi and Lysyanskaya**, 2012.
- `bulletproofs`: Zero-knowledge proof scheme from [Short proofs for Confidential Transactions](https://eprint.iacr.org/2017/1066.pdf), 2017. This implementation is derived from the one by [dalek cryptography](https://github.com/dalek-cryptography/bulletproofs) with some borrowing from the [curve tree](https://github.com/simonkamp/curve-trees/tree/main/bulletproofs) fork and [Alex Ozdemir's](https://github.com/alex-ozdemir/bulletproofs) arkworks version. Used under the MIT license.
- `macros`: Various utilities for generating test/bench/e2e boilerplate. Also from CDLS, but heavily modified.
- `t256` and `t384`: Elliptic curve implementations of the "Thom" representation of NIST-256 and NIST-384 curves (see [ZKAttest](https://eprint.iacr.org/2021/1183)) using the [arkworks](https://arkworks.rs) framework. These are also from the CDLS library. This is only for testing and should not be used in the whole boomerang protocol.
- `tsecp256k1` and `tsecq256k1`; Elliptic curve implementations of secp256k1 and secq256k1 2-cycle curves using the [arkworks](https://arkworks.rs) framework. These are the curves used in Boomerang.
