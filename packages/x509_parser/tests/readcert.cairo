use x509_parser::prelude::*;
use crate::assets::{IGCA_DER, MINIMAL_CRL_DER};

#[test]
fn test_x509_parser() {
    let res = parse_x509_certificate(@IGCA_DER.span());
    match res {
        Ok((
            e, cert,
        )) => {
            assert!(e.is_empty());
            //
            let tbs_cert = cert.tbs_certificate;
            assert_eq!(tbs_cert.version, X509VersionTrait::v3());
        },
        Result::Err(err) => panic!("x509 parsing failed: {:?}", err),
    }
}

#[test]
fn test_crl_parse_minimal() {
    match parse_x509_crl(@MINIMAL_CRL_DER.span()) {
        Ok((
            e, crl,
        )) => {
            assert!(e.is_empty());
            // CAIRO: datetime! macro not available, skipping revocation_date comparison for now
            let revoked_certificates = CertificateRevocationListTrait::iter_revoked_certificates(
                @crl,
            );
            assert_eq!(SpanTrait::len(*revoked_certificates), 1);
            let revoked_cert_0 = SpanTrait::at(*revoked_certificates, 0);
            assert_eq!(*revoked_cert_0.serial(), 42_u256);
            assert!(revoked_cert_0.extensions().is_empty());
            assert!(crl.tbs_cert_list.extensions().is_empty());
        },
        Result::Err(err) => panic!("x509 parsing failed: {:?}", err),
    }
}
