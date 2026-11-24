.PHONY: all build test lint deny fmt deb static builder-image clean

all: lint test build

build:
	cargo build --release --locked --workspace

test:
	cargo test --workspace --locked

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo run --locked -q -p hvpatch-tool -- lint --catalog catalog

# Licenses and RustSec advisories of all dependencies (needs cargo-deny).
deny:
	cargo deny check

fmt:
	cargo fmt --all

# Static agent binary (needs musl-tools for the TLS backend).
static:
	cargo build --release --locked -p hvpatch --target x86_64-unknown-linux-musl

# Debian package of the agent (run on Debian trixie / Proxmox VE 9).
deb:
	dpkg-buildpackage -us -uc -b

# Builder container for livepatch modules (see docs/self-hosting.md).
ENGINE ?= podman
builder-image:
	command -v rustup >/dev/null && rustup target add x86_64-unknown-linux-musl || true
	cargo build --release --locked -p hvpatch-tool --target x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/hvpatch-tool builder/hvpatch-tool
	$(ENGINE) build -t hvpatch-builder builder/

clean:
	cargo clean
