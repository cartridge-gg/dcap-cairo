use asn1::{FromDer, HeaderTrait, Oid, SpanU8CheckDerConstraints, Tag};
use der_parser::ber::{BerObjectTrait, parse_ber_bool};
use der_parser::der::{*, parse_der_sequence_defined_g};
use der_parser::error::BerError;
use nom::combinator::{all_consuming, complete, opt};
use nom::multi::many0;
use nom::{Err, IResult};
use oid_registry::*;
use crate::error::{X509Error, X509Result};
use crate::x509::RelativeDistinguishedName;

mod generalname;

pub use generalname::*;

/// X.509 version 3 extension.
#[derive(Drop, Debug)]
pub struct X509Extension {
    /// OID describing the extension content
    pub oid: Oid,
    /// Boolean value describing the 'critical' attribute of the extension
    ///
    /// An extension includes the boolean critical, with a default value of FALSE.
    pub critical: bool,
    /// Raw content of the extension
    pub value: @Span<u8>,
    pub(crate) parsed_extension: ParsedExtension,
}

#[generate_trait]
pub impl X509ExtensionImpl of X509ExtensionTrait {
    /// Return the extension type or `UnsupportedExtension` if the extension is not implemented.
    #[inline]
    fn parsed_extension(self: @X509Extension) -> @ParsedExtension {
        self.parsed_extension
    }
}

/// <pre>
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING  }
/// </pre>
pub impl X509ExtensionFromDer of FromDer<X509Extension, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<X509Extension> {
        X509ExtensionParserTrait::new().parse(bytes)
    }
}

/// `X509Extension` parser builder
#[derive(Drop, Debug)]
pub struct X509ExtensionParser {
    deep_parse_extensions: bool,
}

#[generate_trait]
impl X509ExtensionParserImpl of X509ExtensionParserTrait {
    fn new() -> X509ExtensionParser {
        X509ExtensionParser { deep_parse_extensions: true }
    }

    fn with_deep_parse_extensions(
        self: X509ExtensionParser, deep_parse_extensions: bool,
    ) -> X509ExtensionParser {
        X509ExtensionParser { deep_parse_extensions }
    }

    // CAIRO: Turned `Parser` impl into method.
    fn parse(
        self: @X509ExtensionParser, input: @Span<u8>,
    ) -> IResult<@Span<u8>, X509Extension, X509Error> {
        parse_der_sequence_defined_g(
            |i, _hdr, _consumed| -> IResult<@Span<u8>, X509Extension, BerError> {
                let (i, oid) = FromDer::<Oid>::from_der(i)?;
                let (i, critical) = der_read_critical(i)?;
                let (i, value) = FromDer::<Span<u8>>::from_der(i)?;
                let (i, parsed_extension) = if *self.deep_parse_extensions {
                    parser::parse_extension(i, @value, @oid)?
                } else {
                    (@array![].span(), ParsedExtension::Unparsed)
                };
                let ext = X509Extension { oid, critical, value: @value, parsed_extension };
                Ok((i, ext))
            },
            input,
        )
            .map_err(|_err| X509Error::InvalidExtensions.into())
    }
}

#[derive(Drop, Debug)]
pub enum ParsedExtension {
    /// Crate parser does not support this extension (yet)
    UnsupportedExtension: Oid,
    ParseError: nom::Err<BerError>,
    /// Section 4.2.1.1 of rfc 5280
    AuthorityKeyIdentifier,
    /// Section 4.2.1.2 of rfc 5280
    SubjectKeyIdentifier,
    /// Section 4.2.1.3 of rfc 5280
    KeyUsage,
    /// Section 4.2.1.4 of rfc 5280
    CertificatePolicies,
    /// Section 4.2.1.5 of rfc 5280
    PolicyMappings,
    /// Section 4.2.1.6 of rfc 5280
    SubjectAlternativeName,
    /// Section 4.2.1.7 of rfc 5280
    IssuerAlternativeName,
    /// Section 4.2.1.9 of rfc 5280
    BasicConstraints: BasicConstraints,
    /// Section 4.2.1.10 of rfc 5280
    NameConstraints,
    /// Section 4.2.1.11 of rfc 5280
    PolicyConstraints,
    /// Section 4.2.1.12 of rfc 5280
    ExtendedKeyUsage,
    /// Section 4.2.1.13 of rfc 5280
    CRLDistributionPoints: CRLDistributionPoints,
    /// Section 4.2.1.14 of rfc 5280
    InhibitAnyPolicy,
    /// Section 4.2.2.1 of rfc 5280
    AuthorityInfoAccess,
    /// Netscape certificate type (subject is SSL client, an SSL server, or a CA)
    NSCertType,
    /// Netscape certificate comment
    NsCertComment,
    /// Section 5.2.5 of rfc 5280
    IssuingDistributionPoint,
    /// Section 5.3.1 of rfc 5280
    CRLNumber,
    /// Section 5.3.1 of rfc 5280
    ReasonCode,
    /// Section 5.3.3 of rfc 5280
    InvalidityDate,
    /// rfc 6962
    SCT,
    /// Unparsed extension (was not requested in parsing options)
    Unparsed,
}

/// Identifies whether the subject of the certificate is a CA, and the max validation depth.
#[derive(Drop, Debug)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u32>,
}

#[derive(Drop, Debug)]
pub struct CRLDistributionPoints {
    pub points: Array<CRLDistributionPoint>,
}

#[derive(Drop, Debug)]
pub struct CRLDistributionPoint {
    pub distribution_point: Option<DistributionPointName>,
    pub reasons: Option<ReasonFlags>,
    pub crl_issuer: Option<Array<GeneralName>>,
}

#[derive(Drop, Debug)]
pub enum DistributionPointName {
    FullName: Array<GeneralName>,
    NameRelativeToCRLIssuer: RelativeDistinguishedName,
}

#[derive(Drop, Debug)]
pub struct ReasonFlags {
    pub flags: u16,
}

pub(crate) mod parser {
    use asn1::TAG_BITSTRING;
    use der_parser::ber::BerObject;
    use der_parser::der::{
        parse_der_sequence_defined_g, parse_der_sequence_of_v, parse_der_tagged_explicit_g,
        parse_der_tagged_implicit,
    };
    use der_parser::error::BerResult;
    use nom::combinator::{complete, map, opt};
    use nom::multi::many1;
    use crate::extensions::*;

    // look into the parser map if the extension is known, and parse it
    // otherwise, leave it as UnsupportedExtension
    fn parse_extension0(
        orig_i: @Span<u8>, i: @Span<u8>, oid: @Oid,
    ) -> IResult<@Span<u8>, ParsedExtension, BerError> {
        // CAIRO: Rewrote `EXTENSION_PARSERS`.
        if *oid == oid_x509_ext_basic_constraints() {
            match parse_basicconstraints_ext(i) {
                Ok((_, ext)) => Ok((orig_i, ext)),
                Result::Err(error) => Ok((orig_i, ParsedExtension::ParseError(error))),
            }
        } else if *oid == oid_x509_ext_crl_distribution_points() {
            match parse_crldistributionpoints_ext(i) {
                Ok((_, ext)) => Ok((orig_i, ext)),
                Result::Err(error) => Ok((orig_i, ParsedExtension::ParseError(error))),
            }
        } else {
            Ok((orig_i, ParsedExtension::UnsupportedExtension(*oid)))
        }
    }

    pub(crate) fn parse_extension(
        orig_i: @Span<u8>, i: @Span<u8>, oid: @Oid,
    ) -> IResult<@Span<u8>, ParsedExtension, BerError> {
        parse_extension0(orig_i, i, oid)
    }

    /// Parse a "Basic Constraints" extension
    ///
    /// <pre>
    ///   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
    ///   BasicConstraints ::= SEQUENCE {
    ///        cA                      BOOLEAN DEFAULT FALSE,
    ///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    /// </pre>
    ///
    /// Note the maximum length of the `pathLenConstraint` field is limited to the size of a 32-bits
    /// unsigned integer, and parsing will fail if value if larger.
    pub(crate) fn parse_basicconstraints(
        i: @Span<u8>,
    ) -> IResult<@Span<u8>, BasicConstraints, BerError> {
        let (rem, obj) = parse_der_sequence(i)?;
        if let Ok(seq) = obj.as_sequence() {
            let (ca, path_len_constraint) = if seq.len() == 0 {
                (false, None)
            } else if seq.len() == 1 {
                if let Ok(b) = seq[0].as_bool() {
                    (b, None)
                } else if let Ok(u) = seq[0].as_u32() {
                    (false, Some(u))
                } else {
                    return Result::Err(Err::Error(BerError::InvalidTag));
                }
            } else if seq.len() == 2 {
                let ca = seq[0].as_bool().or(Result::Err(Err::Error(BerError::InvalidLength)))?;
                let pl = seq[1].as_u32().or(Result::Err(Err::Error(BerError::InvalidLength)))?;
                (ca, Some(pl))
            } else {
                return Result::Err(Err::Error(BerError::InvalidLength));
            };
            Ok((rem, BasicConstraints { ca, path_len_constraint }))
        } else {
            Result::Err(Err::Error(BerError::InvalidLength))
        }
    }

    fn parse_basicconstraints_ext(i: @Span<u8>) -> IResult<@Span<u8>, ParsedExtension, BerError> {
        map(
            |input: @Span<u8>| parse_basicconstraints(input),
            |o1| ParsedExtension::BasicConstraints(o1),
            i,
        )
    }

    // DistributionPointName ::= CHOICE {
    //     fullName                [0]     GeneralNames,
    //     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    fn parse_distributionpointname(
        i: @Span<u8>,
    ) -> IResult<@Span<u8>, DistributionPointName, BerError> {
        let (rem, header) = der_read_element_header(i)?;
        if *header.tag().tag == 0 {
            let (rem, names) = many1(
                |i: @Span<u8>| {
                    complete(|i: @Span<u8>| {
                        parse_generalname(i)
                    }, i)
                }, rem,
            )?;
            Ok((rem, DistributionPointName::FullName(names)))
        } else if *header.tag().tag == 1 {
            panic!("TODO: parse_distributionpointname")
        } else {
            Result::Err(Err::Error(BerError::InvalidTag))
        }
    }

    fn parse_implicit_tagged_reasons(tag: u32, i: @Span<u8>) -> BerResult<ReasonFlags> {
        let (rem, obj) = parse_der_tagged_implicit(
            tag, |i, hdr, depth| {
                parse_der_content(TAG_BITSTRING, i, hdr.clone(), depth)
            }, i,
        )?;
        parse_reasons(rem, obj)
    }

    // ReasonFlags ::= BIT STRING {
    // unused                  (0),
    // keyCompromise           (1),
    // cACompromise            (2),
    // affiliationChanged      (3),
    // superseded              (4),
    // cessationOfOperation    (5),
    // certificateHold         (6),
    // privilegeWithdrawn      (7),
    // aACompromise            (8) }
    fn parse_reasons(rem: @Span<u8>, obj: BerObject) -> BerResult<ReasonFlags> {
        panic!("TODO: parse_reasons")
    }

    fn parse_crlissuer_content(i: @Span<u8>) -> BerResult<Array<GeneralName>> {
        panic!("TODO: parse_crlissuer_content")
    }

    // DistributionPoint ::= SEQUENCE {
    //     distributionPoint       [0]     DistributionPointName OPTIONAL,
    //     reasons                 [1]     ReasonFlags OPTIONAL,
    //     cRLIssuer               [2]     GeneralNames OPTIONAL }
    pub(crate) fn parse_crldistributionpoint(
        i: @Span<u8>,
    ) -> IResult<@Span<u8>, CRLDistributionPoint, BerError> {
        parse_der_sequence_defined_g(
            |content, _hdr, _consumed| -> IResult<@Span<u8>, CRLDistributionPoint, BerError> {
                let (rem, distribution_point) = opt(
                    |i: @Span<u8>| -> IResult<@Span<u8>, DistributionPointName, BerError> {
                        complete(
                            |i: @Span<u8>| {
                                parse_der_tagged_explicit_g(
                                    0_u32, |b: @Span<u8>, _hdr| parse_distributionpointname(b), i,
                                )
                            },
                            i,
                        )
                    },
                    content,
                )?;
                let (rem, reasons) = opt(
                    |i: @Span<u8>| -> IResult<@Span<u8>, ReasonFlags, BerError> {
                        complete(|i: @Span<u8>| parse_implicit_tagged_reasons(1, i), i)
                    },
                    rem,
                )?;
                let (rem, crl_issuer) = opt(
                    |i: @Span<u8>| -> IResult<@Span<u8>, Array<GeneralName>, BerError> {
                        complete(
                            |i: @Span<u8>| {
                                parse_der_tagged_implicit_g(
                                    2_u32,
                                    |i: @Span<u8>, _hdr, _depth| parse_crlissuer_content(i),
                                    i,
                                )
                            },
                            i,
                        )
                    },
                    rem,
                )?;
                let crl_dp = CRLDistributionPoint { distribution_point, reasons, crl_issuer };
                Ok((rem, crl_dp))
            },
            i,
        )
    }

    pub(crate) fn parse_crldistributionpoints(
        i: @Span<u8>,
    ) -> IResult<@Span<u8>, CRLDistributionPoints, BerError> {
        let (ret, crldps) = parse_der_sequence_of_v(
            |i| -> IResult<@Span<u8>, CRLDistributionPoint, BerError> {
                parse_crldistributionpoint(i)
            },
            i,
        )?;
        Ok((ret, CRLDistributionPoints { points: crldps }))
    }

    fn parse_crldistributionpoints_ext(
        i: @Span<u8>,
    ) -> IResult<@Span<u8>, ParsedExtension, BerError> {
        map(
            |input: @Span<u8>| parse_crldistributionpoints(input),
            |o1| ParsedExtension::CRLDistributionPoints(o1),
            i,
        )
    }
}

/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
pub(crate) fn parse_extension_sequence(i: @Span<u8>) -> X509Result<Array<X509Extension>> {
    parse_der_sequence_defined_g(
        |a, _hdr, _consumed| -> IResult<@Span<u8>, Array<X509Extension>, X509Error> {
            all_consuming(
                |a: @Span<u8>| {
                    many0(
                        |a: @Span<u8>| {
                            complete(|a: @Span<u8>| {
                                FromDer::<X509Extension>::from_der(a)
                            }, a)
                        },
                        a,
                    )
                },
                a,
            )
        },
        i,
    )
}

pub(crate) fn parse_extensions(
    i: @Span<u8>, explicit_tag: Tag,
) -> X509Result<Array<X509Extension>> {
    if i.is_empty() {
        return Result::Ok((i, array![]));
    }

    match der_read_element_header(i) {
        Ok((
            rem, hdr,
        )) => {
            if *hdr.tag() != explicit_tag {
                return Result::Err(Err::Error(X509Error::InvalidExtensions));
            }
            all_consuming(|input| parse_extension_sequence(input), rem)
        },
        Result::Err(_) => Result::Err(X509Error::InvalidExtensions.into()),
    }
}

/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
pub(crate) fn parse_extension_envelope_sequence(i: @Span<u8>) -> X509Result<Array<X509Extension>> {
    parse_der_sequence_defined_g(
        |a, _hdr, _consumed| -> IResult<@Span<u8>, Array<X509Extension>, X509Error> {
            all_consuming(
                |a: @Span<u8>| {
                    many0(
                        |a: @Span<u8>| {
                            complete(
                                |a: @Span<u8>| {
                                    X509ExtensionParserTrait::new()
                                        .with_deep_parse_extensions(false)
                                        .parse(a)
                                },
                                a,
                            )
                        },
                        a,
                    )
                },
                a,
            )
        },
        i,
    )
}

pub(crate) fn parse_extensions_envelope(
    i: @Span<u8>, explicit_tag: Tag,
) -> X509Result<Array<X509Extension>> {
    if i.is_empty() {
        return Ok((i, array![]));
    }

    match der_read_element_header(i) {
        Ok((
            rem, hdr,
        )) => {
            if *hdr.tag() != explicit_tag {
                return Result::Err(Err::Error(X509Error::InvalidExtensions));
            }
            all_consuming(|input| parse_extension_envelope_sequence(input), rem)
        },
        Result::Err(_) => Result::Err(X509Error::InvalidExtensions.into()),
    }
}

fn der_read_critical(i: @Span<u8>) -> IResult<@Span<u8>, bool, BerError> {
    // Some certificates do not respect the DER BOOLEAN constraint (true must be encoded as 0xff)
    // so we attempt to parse as BER
    let (rem, obj) = opt(|input| parse_ber_bool(input), i)?;
    let value = obj
        .map(|o| o.as_bool().unwrap_or_default()) // unwrap cannot fail, we just read a bool
        .unwrap_or(false) // default critical value
        ;
    Ok((rem, value))
}
