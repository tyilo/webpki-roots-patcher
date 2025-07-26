use clap::{Parser, ValueEnum};

#[derive(Clone, Copy, ValueEnum)]
enum TlsImplementation {
    Native,
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
        TlsImplementation::Native => builder.use_native_tls(),
        TlsImplementation::RustlsNativeRoots => builder
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .tls_built_in_native_certs(true),
        TlsImplementation::RustlsWebpkiRoots => builder
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .tls_built_in_webpki_certs(true),
    };

    let client = builder.build().unwrap();

    let r = client.get(args.url).send().await;
    println!("Status: {:?}", r.as_ref().map(|r| r.status()));
    if let Ok(r) = r {
        println!("Body length: {:?}", r.bytes().await.map(|b| b.len()));
    }
}
