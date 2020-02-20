local_debug:
	cargo build --features nowarnings
arm_release:
	RUSTFLAGS='-C link-arg=-s' cargo build --target=armv7-unknown-linux-gnueabi --release
test:
	cargo test --features nowarnings