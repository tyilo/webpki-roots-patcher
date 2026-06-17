#![feature(gen_blocks)]

mod memory;

use std::sync::LazyLock;

use bstr::ByteSlice;
use ctor::ctor;
use region::Protection;
use rustls_pki_types::{CertificateDer, TrustAnchor, pem::PemObject};
use webpki::anchor_from_trusted_cert;

use crate::memory::MemoryScanner;

static DEBUG: LazyLock<bool> =
    LazyLock::new(|| std::env::var("WEBPKI_ROOTS_PATCHER_DEBUG").is_ok_and(|v| !v.is_empty()));

macro_rules! log {
    ($($arg:tt)*) => {{
        if *DEBUG {
            eprintln!($($arg)*);
        }
    }};
}

#[allow(unused)]
mod type_layouts {
    use std::ptr::NonNull;

    const TLS_SERVER_ROOTS: &[TrustAnchor] = &TLS_SERVER_ROOTS_ARRAY;
    const TLS_SERVER_ROOTS_ARRAY: [TrustAnchor; 0] = [];

    #[repr(C)]
    struct TrustAnchor {
        subject: Der,
        subject_public_key_info: Der,
        name_constraints: Option<Der>,
    }

    #[repr(C)]
    pub(crate) struct Der {
        // Missing if `rustls-pki-types` is compiled without the `alloc` feature
        variant: usize,
        ptr: NonNull<u8>,
        len: usize,
    }
}

fn find_root_to_replace() -> Option<&'static TrustAnchor<'static>> {
    for root in webpki_roots::TLS_SERVER_ROOTS {
        if root.name_constraints.is_some() {
            continue;
        }
        if root.subject.contains_str("DigiCert Global Root G2") {
            return Some(root);
        }
    }
    None
}

fn print_u64s(bytes: &[u8]) {
    const U64_BYTES: usize = (u64::BITS / 8) as usize;

    let (chunks, _) = bytes.as_chunks::<U64_BYTES>();
    for chunk in chunks {
        log!(
            "0x{:0width$x}",
            u64::from_le_bytes(*chunk),
            width = 2 * U64_BYTES
        );
    }
}

fn replace_root(to_replace: &TrustAnchor<'static>, new_root: &TrustAnchor<'static>) {
    let scanner = MemoryScanner::new();

    for (subject_bytes_region, subject_bytes_addr) in scanner
        .find_bytes(&to_replace.subject, |region| {
            region.protection() == Protection::READ
        })
    {
        log!("Found subject bytes at 0x{subject_bytes_addr:x} in {subject_bytes_region:?}");
        if subject_bytes_addr == to_replace.subject.as_ptr().addr() {
            log!("  Skipping as this is our own copy of the certificate.");
            continue;
        }

        let subject_addr_bytes = subject_bytes_addr.to_le_bytes();
        let subject_len_bytes = to_replace.subject.len().to_le_bytes();
        let subject_slice_bytes = [subject_addr_bytes, subject_len_bytes].concat();

        for (subject_slice_region, subject_slice_addr) in
            scanner.find_bytes(&subject_slice_bytes, |r| r.protection() == Protection::READ)
        {
            log!("  Found subject slice at 0x{subject_slice_addr:x} at {subject_slice_region:?}");

            let mut bytes = scanner
                .read_bytes(
                    subject_slice_addr,
                    2 * std::mem::size_of::<type_layouts::Der>(),
                )
                .unwrap();
            log!("Current memory (u64's) @ 0x{subject_slice_addr:x}:");
            print_u64s(&bytes);

            let new_subject_slice = new_root.subject.as_ref();
            bytes[0..8].copy_from_slice(&new_subject_slice.as_ptr().addr().to_le_bytes());
            bytes[8..16].copy_from_slice(&new_subject_slice.len().to_le_bytes());

            let new_subject_public_key_info_slice = new_root.subject_public_key_info.as_ref();
            // bytes[16..24] variant
            bytes[24..32].copy_from_slice(
                &new_subject_public_key_info_slice
                    .as_ptr()
                    .addr()
                    .to_le_bytes(),
            );
            bytes[32..40].copy_from_slice(&new_subject_public_key_info_slice.len().to_le_bytes());

            log!("Patched memory (u64's) @ 0x{subject_slice_addr:x}:");
            print_u64s(&bytes);

            unsafe { scanner.write_bytes(subject_slice_addr, &bytes) }.unwrap();
        }
        log!();
    }
}

fn print_anchor(anchor: &TrustAnchor<'static>) {
    log!("TrustAnchor @ {:?} {{", &raw const *anchor);
    log!(
        "  subject @ {:?}: {:?}",
        &raw const anchor.subject,
        &raw const *anchor.subject.as_ref()
    );
    log!(
        "  subject_public_key_info @ {:?}: {:?}",
        &raw const anchor.subject_public_key_info,
        &raw const *anchor.subject_public_key_info.as_ref()
    );
    log!(
        "  name_constraints @ {:?}: {:?}",
        &raw const anchor.name_constraints,
        anchor.name_constraints.as_deref(),
    );
    log!("}}");
}

fn patch_roots() {
    let Ok(root_pem_path) = std::env::var("SSL_CERT_FILE") else {
        log!("SSL_CERT_FILE environment variable not found.");
        return;
    };

    let root_cert = Box::leak(Box::new(
        CertificateDer::from_pem_file(root_pem_path).unwrap(),
    ));
    let root_anchor = Box::leak(Box::new(anchor_from_trusted_cert(root_cert).unwrap()));
    log!("Root anchor to patch in: TrustAnchor {{");
    log!(
        "  subject: Der::from_slice(b\"{}\"),",
        root_anchor.subject.escape_ascii()
    );
    log!(
        "  subject_public_key_info: Der::from_slice(b\"{}\"),",
        root_anchor.subject_public_key_info.escape_ascii()
    );
    log!("  name_constraints: None,");
    log!("}}");

    let to_replace = find_root_to_replace().unwrap();
    assert_eq!(to_replace.name_constraints, None);

    log!(
        "TLS_SERVER_ROOTS: {:?}",
        &raw const *webpki_roots::TLS_SERVER_ROOTS
    );

    log!("Replace ");
    print_anchor(to_replace);
    log!("with ");
    print_anchor(root_anchor);

    replace_root(to_replace, root_anchor);
}

#[ctor(unsafe)]
fn init() {
    log!("== webpki-roots-patcher start ==");
    patch_roots();
    log!("== webpki-roots-patcher end ==");
}
