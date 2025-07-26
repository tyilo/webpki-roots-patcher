# webpki-roots-patcher

Patch the list of CA certificates provided by [`webpki-roots`](https://github.com/rustls/webpki-roots) used in any binary, such as binaries using [`reqwest`](https://github.com/seanmonstar/reqwest) v0.12 with the `rustls-tls`/`rustls-tls-webpki-roots` feature.

This is useful when intercepting HTTPS traffic with tools such as [mitmproxy](https://mitmproxy.org/) and [HTTP Toolkit](https://httptoolkit.com/).

The patching works by setting the [`LD_PRELOAD`](https://www.man7.org/linux/man-pages/man8/ld.so.8.html) environment variable to the path of the built dynamic library and setting the `SSL_CERT_FILE` environment variable to the path of a PEM certificate to patch in. All processes started will then load the dynamic library which will:
- Read the certificate stored in the file referenced by the `SSL_CERT_FILE` environment variable
- Try to find the list of `webpki-roots` CA certificates in the process' memory
- Patch the list by swapping a known CA certificate out with the provided certificate

## Building

```
cargo build --release
```

## Usage

A test binary is provided in `test-binary`:
```
$ cargo build --manifest-path test-binary/Cargo.toml
$ test-binary/target/debug/test-binary rustls-webpki-roots https://example.org/
Status: Ok(200)
Body length: Ok(1256)
```

Run `mitmproxy` in a new terminal and then see that intercepting the traffic fails:
```
$ export HTTPS_PROXY=https://localhost:8080/
$ export SSL_CERT_FILE=$HOME/.mitmproxy/mitmproxy-ca-cert.pem
$ test-binary/target/debug/test-binary rustls-webpki-roots https://example.org/
Status: Err(reqwest::Error { kind: Request, url: "https://example.org/", source: hyper_util::client::legacy::Error(Connect, ConnectFailed(Custom { kind: Other, error: Custom { kind: InvalidData, error: InvalidCertificate(UnknownIssuer) } })) })
```

By injecting the dynamic library the traffic is now successfully intercepted:
```
$ LD_PRELOAD=target/release/libwebpki_roots_patcher.so test-binary/target/debug/test-binary rustls-webpki-roots https://example.org/ 
Status: Ok(200)
Body length: Ok(1256)
```

By setting the `WEBPKI_ROOTS_PATCHER_DEBUG` environment variable some debug logs will be printed:
```
$ WEBPKI_ROOTS_PATCHER_DEBUG=1 LD_PRELOAD=target/release/libwebpki_roots_patcher.so test-binary/target/debug/test-binary rustls-webpki-roots https://example.org/
== webpki-roots-patcher start ==
Root anchor to patch in: TrustAnchor {
  subject: Der::from_slice(b"1\x120\x10\x06\x03U\x04\x03\x0c\tmitmproxy1\x120\x10\x06\x03U\x04\n\x0c\tmitmproxy"),
  subject_public_key_info: Der::from_slice(b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xb7\xc7r\xaf\xed\xc9\xd9>pX\\\xf5\xccP\xa7e\x9d\xcd\xed\xe3\x13\xff\x95\xc7\x1f\x91\xd1\x86\xc8\xe1\xe6\xbb;\x7f\xca\xc5+!T!\x94\xe9\xe0\xd8`\xa0\x9cN\xd7\xfaT\x83W\x8b\x9f,\xeb\xffU\x83\xf7\xb1\xcf\xe5\x96K\xd2=\x86\"\xe5)\r\x11\x9dr\xe0\xa6\x08\xaf\x06\x1e\\\xc7\x0b\xf8\xf39\xc7.\x00ru\xcfo\x07b,\xd1\xf7\xed\xe3\x17\x8f\n\xed\xcb\xbf\x85L\xa9\xc8y\xb6b\x9db\xd0d\r{\xd9\x1d.\xc0@\x99\x84\x08\xa4\x90\xc5vb\x10\xf9\xeb\xd6FL\xafS+\xe9\xcdy43Naf^\xa6\xf6\x86\x0e\xcd\xf1>\x07\x0f\x1f\x16u$\xf5=R(z\x1b\x1b9\xa0\xf5\xf7+zg\xac4\xbcL\xb0m\xdd\xd7\xdb\x92X\xd4~\x9f\xbf\x1fd\x0b\xc6\xa1\x15\x1e\x05\xa1\x99\x91U\xaf4v\x81\x0b\xe9\xc6\x8cp\x9b\xaf\x8a\x0f)w\x05\xb4\x05\x94\xba\xa6\xc3\xb0-\xf5\xce\xac\x14\x1b5_\xdc\x10yr0\xb11\r\xe7.v\x8b~\n\x11\xad<\xcd\xbd\x02\x03\x01\x00\x01"),
  name_constraints: None,
}
TLS_SERVER_ROOTS: Pointer { addr: 0x1499bbb9d848, metadata: 144 }
Replace TrustAnchor @ 0x1499bbb9f8a0 {
  subject @ 0x1499bbb9f8a0: Pointer { addr: 0x1499bbb88b02, metadata: 97 }
  subject_public_key_info @ 0x1499bbb9f8b8: Pointer { addr: 0x1499bbb88b63, metadata: 290 }
  name_constraints @ 0x1499bbb9f8d0: None
}
with TrustAnchor @ 0x56341efc27b0 {
  subject @ 0x56341efc27b0: Pointer { addr: 0x56341efc303e, metadata: 40 }
  subject_public_key_info @ 0x56341efc27c8: Pointer { addr: 0x56341efc306a, metadata: 290 }
  name_constraints @ 0x56341efc27e0: None
}
Found subject bytes at 0x1499bbb88b02 in Region { base: 0x1499bbb7a000, reserved: false, guarded: false, protection: READ, max_protection: NONE, shared: false, size: 143360 }
  Skipping as this is our own copy of the certificate.
Found subject bytes at 0x5634124bdeef in Region { base: 0x563412497000, reserved: false, guarded: false, protection: READ, max_protection: NONE, shared: false, size: 2035712 }
  Found subject slice at 0x56341268e218 at Region { base: 0x563412688000, reserved: false, guarded: false, protection: READ, max_protection: NONE, shared: false, size: 397312 }
Current memory (u64's) @ 0x56341268e218:
0x00005634124bdeef
0x0000000000000061
0x8000000000000000
0x00005634124bdf50
0x0000000000000122
0x8000000000000001
Patched memory (u64's) @ 0x56341268e218:
0x000056341efc303e
0x0000000000000028
0x8000000000000000
0x000056341efc306a
0x0000000000000122
0x8000000000000001

== webpki-roots-patcher end ==
Status: Ok(200)
Body length: Ok(1256)
```
