use asn1::{BitString, FromDer, Oid, OptionTaggedFromDer, TaggedImplicit, TaggedValueTrait};
use der_parser::*;
use der_parser::der::*;
use der_parser::error::*;
use nom::IResult;
use crate::error::{X509Error, X509Result};
use crate::extensions::*;
use crate::time::ASN1Time;
use crate::x509::{
    AlgorithmIdentifier, SubjectPublicKeyInfo, X509Name, X509Version, X509VersionImpl, parse_serial,
    parse_signature_value,
};

/// An X.509 v3 Certificate.
#[derive(Drop, Debug)]
pub struct X509Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitString,
}

pub impl X509CertificateFromDer of FromDer<X509Certificate, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<X509Certificate> {
        X509CertificateParserImpl::new().parse(bytes)
    }
}

/// X.509 Certificate parser.
#[derive(Drop, Debug)]
pub struct X509CertificateParser {
    deep_parse_extensions: bool,
}

#[generate_trait]
impl X509CertificateParserImpl of X509CertificateParserTrait {
    fn new() -> X509CertificateParser {
        X509CertificateParser { deep_parse_extensions: true }
    }

    fn parse(
        self: @X509CertificateParser, input: @Span<u8>,
    ) -> IResult<@Span<u8>, X509Certificate, X509Error> {
        parse_der_sequence_defined_g::<
            _, _, X509Error,
        >(
            |i, _hdr, _consumed| -> IResult<@Span<u8>, X509Certificate, X509Error> {
                // pass options to TbsCertificate parser
                let mut tbs_parser = TbsCertificateParserImpl::new()
                    .with_deep_parse_extensions(*self.deep_parse_extensions);
                let (i, tbs_certificate) = tbs_parser.parse(i)?;
                let (i, signature_algorithm) = FromDer::<AlgorithmIdentifier>::from_der(i)?;
                let (i, signature_value) = parse_signature_value(i)?;
                let cert = X509Certificate {
                    tbs_certificate, signature_algorithm, signature_value,
                };
                Ok((i, cert))
            },
            input,
        )
    }
}

/// The sequence `TBSCertificate` contains information associated with the
/// subject of the certificate and the CA that issued it.
#[derive(Drop, Debug)]
pub struct TbsCertificate {
    pub version: X509Version,
    pub serial: u256,
    pub signature: AlgorithmIdentifier,
    pub issuer: X509Name,
    pub validity: Validity,
    pub subject: X509Name,
    pub subject_pki: SubjectPublicKeyInfo,
    pub issuer_uid: Option<UniqueIdentifier>,
    pub subject_uid: Option<UniqueIdentifier>,
    extensions: Array<X509Extension>,
    pub raw: @Span<u8>,
    pub(crate) raw_serial: @Span<u8>,
}

#[generate_trait]
pub impl TbsCertificateImpl of TbsCertificateTrait {
    /// Get the certificate subject.
    #[inline]
    fn subject(self: @TbsCertificate) -> @X509Name {
        self.subject
    }

    /// Get the certificate issuer.
    #[inline]
    fn issuer(self: @TbsCertificate) -> @X509Name {
        self.issuer
    }

    /// Get the certificate validity.
    #[inline]
    fn validity(self: @TbsCertificate) -> @Validity {
        self.validity
    }

    /// Get the certificate public key information.
    #[inline]
    fn public_key(self: @TbsCertificate) -> @SubjectPublicKeyInfo {
        self.subject_pki
    }

    /// Searches for an extension with the given `Oid`.
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error `DuplicateExtensions` if the extension is present twice or more.
    #[inline]
    fn get_extension_unique(
        self: @TbsCertificate, oid: @Oid,
    ) -> Result<Option<@X509Extension>, X509Error> {
        get_extension_unique(@self.extensions.span(), oid)
    }
}

/// Searches for an extension with the given `Oid`.
///
/// Note: if there are several extensions with the same `Oid`, an error `DuplicateExtensions` is
/// returned.
fn get_extension_unique(
    extensions: @Span<X509Extension>, oid: @Oid,
) -> Result<Option<@X509Extension>, X509Error> {
    let mut res = None;
    for ext in extensions {
        if ext.oid == oid {
            if res.is_some() {
                return Result::Err(X509Error::DuplicateExtensions);
            }
            res = Some(ext);
        }
    }
    Ok(res)
}

/// `TbsCertificate` parser builder.
#[derive(Drop, Debug)]
pub struct TbsCertificateParser {
    deep_parse_extensions: bool,
}

#[generate_trait]
impl TbsCertificateParserImpl of TbsCertificateParserTrait {
    fn new() -> TbsCertificateParser {
        TbsCertificateParser { deep_parse_extensions: true }
    }

    #[inline]
    fn with_deep_parse_extensions(
        self: TbsCertificateParser, deep_parse_extensions: bool,
    ) -> TbsCertificateParser {
        TbsCertificateParser { deep_parse_extensions }
    }

    fn parse(
        self: @TbsCertificateParser, input: @Span<u8>,
    ) -> IResult<@Span<u8>, TbsCertificate, X509Error> {
        let start_i = input;
        parse_der_sequence_defined_g::<
            _, _, X509Error,
        >(
            |i, _hdr, consumed| -> IResult<@Span<u8>, TbsCertificate, X509Error> {
                let (i, version) = X509VersionImpl::from_der_tagged_0(i)?;
                let (i, serial) = parse_serial(i)?;
                let (i, signature) = FromDer::<AlgorithmIdentifier>::from_der(i)?;
                let (i, issuer) = FromDer::<X509Name>::from_der(i)?;
                let (i, validity) = FromDer::<Validity>::from_der(i)?;
                let (i, subject) = FromDer::<X509Name>::from_der(i)?;
                let (i, subject_pki) = FromDer::<SubjectPublicKeyInfo>::from_der(i)?;
                let (i, issuer_uid) = UniqueIdentifierTrait::from_der_issuer(i)?;
                let (i, subject_uid) = UniqueIdentifierTrait::from_der_subject(i)?;
                let (i, extensions) = if *self.deep_parse_extensions {
                    parse_extensions(i, Tag { tag: 3 })?
                } else {
                    parse_extensions_envelope(i, Tag { tag: 3 })?
                };

                // CAIRO: Rewrote `.offset()` as it's impossible to implement in Cairo.
                let len = consumed;

                let (serial0, serial1) = serial;
                let tbs = TbsCertificate {
                    version,
                    serial: serial1,
                    signature,
                    issuer,
                    validity,
                    subject,
                    subject_pki,
                    issuer_uid,
                    subject_uid,
                    extensions,
                    raw: @start_i.slice(0, len),
                    raw_serial: serial0,
                };
                Ok((i, tbs))
            },
            input,
        )
    }
}

#[derive(Drop, Debug, Clone)]
pub struct Validity {
    pub not_before: ASN1Time,
    pub not_after: ASN1Time,
}

pub impl ValidityFromDer of FromDer<Validity, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<Validity> {
        parse_der_sequence_defined_g(
            |i, _hdr, _consumed| -> IResult<@Span<u8>, Validity, X509Error> {
                let (i, not_before) = FromDer::<ASN1Time>::from_der(i)?;
                let (i, not_after) = FromDer::<ASN1Time>::from_der(i)?;
                let v = Validity { not_before, not_after };
                Ok((i, v))
            },
            bytes,
        )
    }
}

#[derive(Drop, Debug, Clone)]
pub struct UniqueIdentifier {
    pub inner: BitString,
}

#[generate_trait]
impl UniqueIdentifierImpl of UniqueIdentifierTrait {
    // issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL
    fn from_der_issuer(i: @Span<u8>) -> X509Result<Option<UniqueIdentifier>> {
        Self::parse::<1>(i).map_err(|_err| X509Error::InvalidIssuerUID.into())
    }

    // subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
    fn from_der_subject(i: @Span<u8>) -> X509Result<Option<UniqueIdentifier>> {
        Self::parse::<2>(i).map_err(|_err| X509Error::InvalidSubjectUID.into())
    }

    // CAIRO: Using tag as runtime parameter instead of const generic
    //
    // Parse a [tag] UniqueIdentifier OPTIONAL
    //
    // UniqueIdentifier  ::=  BIT STRING
    fn parse<const TAG: u32>(i: @Span<u8>) -> BerResult<Option<UniqueIdentifier>> {
        let (rem, unique_id) = OptionTaggedFromDer::<
            TaggedImplicit<BitString, Error, TAG>,
        >::from_der(i)?;
        let unique_id = match unique_id {
            Some(u) => Some(UniqueIdentifier { inner: u.into_inner() }),
            None => None,
        };
        Ok((rem, unique_id))
    }
}
