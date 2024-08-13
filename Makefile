all: build

.PHONY: all help build check test bench clean

help:
	@echo "usage: make {build|test|clean|bench}"

build:
	cargo build

check: test

clean:
	cargo clean

test:
	cargo test --release

e2e:
	@echo "Starting end2end example server and client..."
	cargo build --release --example server
	# Run the server in the background, terminate it after the client
	cargo run --release --example server & \
		export SERVER_PID=$$!; \
		cargo run --release --example client; \
		kill -s HUP $$SERVER_PID
	@echo "Ok"

bench:
	cargo bench
