.PHONY: all build test lint fmt deb static clean

all: lint test build

build:
	cargo build --release --locked --workspace

test:
	cargo test --workspace --locked

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo run --locked -q -p pve-klp-tool -- lint --catalog catalog

fmt:
	cargo fmt --all

# Static agent binary (needs musl-tools for the TLS backend).
static:
	cargo build --release --locked -p pve-klp --target x86_64-unknown-linux-musl

# Debian package of the agent (run on Debian trixie / Proxmox VE 9).
deb:
	dpkg-buildpackage -us -uc -b

clean:
	cargo clean
