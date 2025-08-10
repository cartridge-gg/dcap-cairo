//! Ported from [`x509-parser`](https://crates.io/crates/x509-parser) v0.17.0.

pub mod certificate;
pub mod error;
pub mod extensions;
pub mod prelude;
pub mod revocation_list;
pub mod time;
pub mod x509;
use asn1::FromDer;
use certificate::X509Certificate;
use error::X509Result;
use revocation_list::CertificateRevocationList;

/// Parse a **DER-encoded** X.509 Certificate, and return the remaining of the input and the built
/// object.
#[inline]
pub fn parse_x509_certificate(i: @Span<u8>) -> X509Result<X509Certificate> {
    FromDer::<X509Certificate>::from_der(i)
}

/// Parse a **DER-encoded** X.509 Certificate Revocation List, and return the remaining of the input
/// and the built object.
#[inline]
pub fn parse_x509_crl(i: @Span<u8>) -> X509Result<CertificateRevocationList> {
    FromDer::<CertificateRevocationList>::from_der(i)
}
