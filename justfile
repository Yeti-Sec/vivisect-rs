# rust-vivisect Build Harness

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

build:
    cargo build --release

build-icicle:
    cargo build --release --features icicle

test:
    cargo test

lint:
    cargo clippy

fmt:
    cargo fmt

fmt-check:
    cargo fmt -- --check

check-all: fmt-check lint test

clean:
    cargo clean
