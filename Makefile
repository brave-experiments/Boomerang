prog :=xnixperms

debug ?=

$(info debug is $(debug))

ifdef debug
  release :=
  target :=debug
  extension :=debug
else
  release :=--release
  target :=release
  extension :=
endif

build:
	cargo build $(release)

install:
	cp target/$(target)/$(prog) ~/bin/$(prog)-$(extension)

all: build install

help:
	@echo "usage: make $(prog) [debug=1]"

run:
	cargo build $(release)
	cargo run

test:
	cargo build $(release)
	cargo run
	cargo test
