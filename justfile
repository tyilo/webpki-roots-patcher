url := "https://ifconfig.co/ip"
export SSL_CERT_FILE := env("HOME") / ".config/httptoolkit/ca.pem"
so_name := "libwebpki_roots_patcher.so"

build:
	env
	cargo build

build-release:
	cargo build --release

test: build
	cargo build --manifest-path test-binary/Cargo.toml
	LD_PRELOAD="$PWD/target/debug/{{so_name}}" test-binary/target/debug/test-binary rustls-webpki-roots {{url}}

test-release: build-release
	cargo build --manifest-path test-binary/Cargo.toml --release
	LD_PRELOAD="$PWD/target/release/{{so_name}}" test-binary/target/release/test-binary rustls-webpki-roots {{url}}
