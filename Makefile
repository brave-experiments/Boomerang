build:
	cargo build

all: build

help:
	@echo "usage: make $(prog) [debug=1]"

run:
	cargo build
	cargo run

test:
	cargo build
	cargo test

bench:
	cargo build
	cargo bench
