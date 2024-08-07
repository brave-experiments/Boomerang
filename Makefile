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
	@echo "Starting end2end example server and client..."
	# Build the server explicitly so it doesn't race the client
	cargo build --release --bin server
	# Run the server in the background, terminate it after the client
	cargo run --release --bin server & \
		export SERVER_PID=$$!; \
		cargo run --release --bin client; \
		kill -s HUP $$SERVER_PID
	@echo "Ok"

bench:
	cargo bench
