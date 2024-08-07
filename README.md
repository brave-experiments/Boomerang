# Boomerang

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
