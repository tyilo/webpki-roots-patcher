use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use rustls::RootCertStore;

#[derive(Clone, Copy, ValueEnum)]
enum TlsImplementation {
    Native,
    RustlsPlatformProvider,
    RustlsNativeRoots,
    RustlsWebpkiRoots,
}

#[derive(Parser)]
struct Args {
    tls: TlsImplementation,
    url: reqwest::Url,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let builder = reqwest::Client::builder();
    let builder = match args.tls {
        TlsImplementation::Native => builder.tls_backend_native(),
        TlsImplementation::RustlsPlatformProvider => builder.tls_backend_rustls(),
        TlsImplementation::RustlsNativeRoots => {
            let mut root_store = RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().unwrap() {
                root_store.add(cert).unwrap();
            }
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            builder.tls_backend_preconfigured(tls)
        }
        TlsImplementation::RustlsWebpkiRoots => {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            builder.tls_backend_preconfigured(tls)
        }
    };

    let client = builder.build().unwrap();

    let r = client.get(args.url).send().await;
    println!("Status: {:?}", r.as_ref().map(|r| r.status()));
    if let Ok(r) = r {
        println!("Body length: {:?}", r.bytes().await.map(|b| b.len()));
    }
}
