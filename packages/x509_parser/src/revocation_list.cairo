use asn1::{BitString, FromDer, Tag};
use der_parser::der::{parse_der_sequence_defined_g, parse_der_u32};
use nom::combinator::{all_consuming, complete, map, opt};
use nom::multi::many0;
use nom::{Err, IResult};
use crate::error::{X509Error, X509Result};
use crate::extensions::{X509Extension, parse_extensions};
use crate::time::ASN1Time;
use crate::x509::{AlgorithmIdentifier, X509Name, X509Version, parse_serial, parse_signature_value};

/// An X.509 v2 Certificate Revocation List (CRL).
///
/// X.509 v2 CRLs are defined in [RFC5280](https://tools.ietf.org/html/rfc5280).
#[derive(Drop, Debug)]
pub struct CertificateRevocationList {
    pub tbs_cert_list: TbsCertList,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitString,
}

#[generate_trait]
pub impl CertificateRevocationListImpl of CertificateRevocationListTrait {
    /// Get the version of the encoded certificate
    fn version(self: @CertificateRevocationList) -> @Option<X509Version> {
        self.tbs_cert_list.version
    }

    /// Get the certificate issuer.
    #[inline]
    fn issuer(self: @CertificateRevocationList) -> @X509Name {
        self.tbs_cert_list.issuer
    }

    /// Get the date and time of the last (this) update.
    #[inline]
    fn last_update(self: @CertificateRevocationList) -> @ASN1Time {
        self.tbs_cert_list.this_update
    }

    /// Get the date and time of the next update, if present.
    #[inline]
    fn next_update(self: @CertificateRevocationList) -> @Option<ASN1Time> {
        self.tbs_cert_list.next_update
    }

    // CAIRO: Returns @Span instead of Iterator
    /// Return an iterator over the `RevokedCertificate` objects
    fn iter_revoked_certificates(self: @CertificateRevocationList) -> @Span<RevokedCertificate> {
        @self.tbs_cert_list.revoked_certificates.span()
    }
}

/// <pre>
/// CertificateList  ::=  SEQUENCE  {
///      tbsCertList          TBSCertList,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signatureValue       BIT STRING  }
/// </pre>
impl CertificateRevocationListFromDer of FromDer<CertificateRevocationList, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<CertificateRevocationList> {
        parse_der_sequence_defined_g(
            |i, _hdr, _consumed| -> IResult<@Span<u8>, CertificateRevocationList, X509Error> {
                let (i, tbs_cert_list) = FromDer::<TbsCertList, X509Error>::from_der(i)?;
                let (i, signature_algorithm) = FromDer::<
                    AlgorithmIdentifier, X509Error,
                >::from_der(i)?;
                let (i, signature_value) = parse_signature_value(i)?;
                let crl = CertificateRevocationList {
                    tbs_cert_list, signature_algorithm, signature_value,
                };
                Ok((i, crl))
            },
            bytes,
        )
    }
}

/// The sequence TBSCertList contains information about the certificates that have
/// been revoked by the CA that issued the CRL.
///
/// RFC5280 definition:
///
/// <pre>
/// TBSCertList  ::=  SEQUENCE  {
///         version                 Version OPTIONAL,
///                                      -- if present, MUST be v2
///         signature               AlgorithmIdentifier,
///         issuer                  Name,
///         thisUpdate              Time,
///         nextUpdate              Time OPTIONAL,
///         revokedCertificates     SEQUENCE OF SEQUENCE  {
///             userCertificate         CertificateSerialNumber,
///             revocationDate          Time,
///             crlEntryExtensions      Extensions OPTIONAL
///                                      -- if present, version MUST be v2
///                                   } OPTIONAL,
///         crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
///                                      -- if present, version MUST be v2
///                             }
/// </pre>
#[derive(Drop, Debug)]
pub struct TbsCertList {
    pub version: Option<X509Version>,
    pub signature: AlgorithmIdentifier,
    pub issuer: X509Name,
    pub this_update: ASN1Time,
    pub next_update: Option<ASN1Time>,
    pub revoked_certificates: Array<RevokedCertificate>,
    extensions: Array<X509Extension>,
    pub(crate) raw: @Span<u8>,
}

#[generate_trait]
pub impl TbsCertListImpl of TbsCertListTrait {
    /// Returns the certificate extensions
    #[inline]
    fn extensions(self: @TbsCertList) -> Span<X509Extension> {
        self.extensions.span()
    }

    #[inline]
    fn data(self: @TbsCertList) -> @Span<u8> {
        *self.raw
    }
}

impl TbsCertListFromDer of FromDer<TbsCertList, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<TbsCertList> {
        let start_i = bytes.clone();
        parse_der_sequence_defined_g(
            |i, _hdr, consumed| -> IResult<@Span<u8>, TbsCertList, X509Error> {
                let (i, version) = opt(
                    |input| {
                        map(|input| parse_der_u32(input), |o1| X509Version { version: o1 }, input)
                    },
                    i,
                )
                    .or(Result::Err(Err::Error(X509Error::InvalidVersion)))?;
                let (i, signature) = FromDer::<AlgorithmIdentifier, X509Error>::from_der(i)?;
                let (i, issuer) = FromDer::<X509Name, X509Error>::from_der(i)?;
                let (i, this_update) = FromDer::<ASN1Time, X509Error>::from_der(i)?;
                let (i, next_update) = opt(|inp| FromDer::<ASN1Time, X509Error>::from_der(inp), i)?;
                let (i, revoked_certificates) = opt(
                    |input| complete(|input| parse_revoked_certificates(input), input), i,
                )?;
                let (i, extensions) = parse_extensions(i, Tag { tag: 0 })?;

                let tbs = TbsCertList {
                    version,
                    signature,
                    issuer,
                    this_update,
                    next_update,
                    revoked_certificates: revoked_certificates.unwrap_or_default(),
                    extensions,
                    raw: @start_i.slice(0, consumed),
                };
                Ok((i, tbs))
            },
            bytes,
        )
    }
}

#[derive(Drop, Debug)]
pub struct RevokedCertificate {
    /// The Serial number of the revoked certificate
    pub user_certificate: u256,
    /// The date on which the revocation occurred is specified.
    pub revocation_date: ASN1Time,
    /// Additional information about revocation
    extensions: Array<X509Extension>,
    pub(crate) raw_serial: Span<u8>,
}

#[generate_trait]
pub impl RevokedCertificateImpl of RevokedCertificateTrait {
    /// Return the serial number of the revoked certificate
    fn serial(self: @RevokedCertificate) -> @u256 {
        self.user_certificate
    }

    /// Get the raw bytes of the certificate serial number
    fn raw_serial(self: @RevokedCertificate) -> @Span<u8> {
        self.raw_serial
    }

    /// Get the CRL entry extensions.
    #[inline]
    fn extensions(self: @RevokedCertificate) -> Span<X509Extension> {
        self.extensions.span()
    }
}

// revokedCertificates     SEQUENCE OF SEQUENCE  {
//     userCertificate         CertificateSerialNumber,
//     revocationDate          Time,
//     crlEntryExtensions      Extensions OPTIONAL
//                                   -- if present, MUST be v2
//                          }  OPTIONAL,
impl RevokedCertificateFromDer of FromDer<RevokedCertificate, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<RevokedCertificate> {
        parse_der_sequence_defined_g(
            |i, _hdr, _consumed| -> IResult<@Span<u8>, RevokedCertificate, X509Error> {
                let (i, (raw_serial, user_certificate)) = parse_serial(i)?;
                let (i, revocation_date) = FromDer::<ASN1Time, X509Error>::from_der(i)?;
                let revoked = RevokedCertificate {
                    user_certificate,
                    revocation_date,
                    // CAIRO: Extensions field omitted - TODO
                    extensions: array![],
                    raw_serial: *raw_serial,
                };
                Ok((i, revoked))
            },
            bytes,
        )
    }
}

fn parse_revoked_certificates(i: @Span<u8>) -> X509Result<Array<RevokedCertificate>> {
    parse_der_sequence_defined_g(
        |a, _hdr, _consumed| -> IResult<@Span<u8>, Array<RevokedCertificate>, X509Error> {
            all_consuming(
                |
                    inp,
                | many0(
                    |i2| complete(|i3| FromDer::<RevokedCertificate, X509Error>::from_der(i3), i2),
                    inp,
                ),
                a,
            )
        },
        i,
    )
}
