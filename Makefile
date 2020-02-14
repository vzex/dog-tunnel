local_debug:
	cargo build
arm_release:
	RUSTFLAGS='-C link-arg=-s' cargo build --target=armv7-unknown-linux-gnueabi --release
