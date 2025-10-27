default: build

fmt:
    cargo fmt

lint:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test

build:
    cargo build --release

clean:
    cargo clean
