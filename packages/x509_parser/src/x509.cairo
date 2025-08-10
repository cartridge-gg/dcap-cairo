use asn1::{
    Any, AnyTrait, BitString, FromBer, FromDer, HeaderTrait, Oid, OptTaggedParser,
    OptTaggedParserTrait, OptionAnyFromDer, ParseResult, TAG_INTEGER, TAG_SEQUENCE, Tag, TagTrait,
    Tagged, U32CheckDerConstraints,
};
use der_parser::*;
use der_parser::der::*;
use der_parser::error::*;
use int_traits::U256FromBytesBe;
use nom::branch::alt;
use nom::combinator::complete;
use nom::multi::{many0, many1};
use nom::{Err, ErrTrait};
use crate::error::{X509Error, X509Result};

#[derive(Drop, Debug, Copy, PartialEq)]
pub struct X509Version {
    pub version: u32,
}

pub const X509VERSION_V1: X509Version = X509Version { version: 0 };

#[generate_trait]
pub impl X509VersionImpl of X509VersionTrait {
    /// Parse `[0]` EXPLICIT Version DEFAULT v1
    fn from_der_tagged_0(i: @Span<u8>) -> X509Result<X509Version> {
        let (rem, opt_version) = Into::<u32, OptTaggedParser>::into(0)
            .parse_der(i, |_unused, data| FromDer::<X509Version>::from_der(data))?;
        let version = opt_version.unwrap_or(X509VERSION_V1);
        Ok((rem, version))
    }

    const fn v1() -> X509Version {
        X509Version { version: 0 }
    }

    const fn v2() -> X509Version {
        X509Version { version: 1 }
    }

    const fn v3() -> X509Version {
        X509Version { version: 2 }
    }
}

// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
pub impl X509VersionFromDer of FromDer<X509Version, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<X509Version> {
        // CAIRO: Rewrote to flatten the `.map()` call.

        let (input, o1) = FromDer::<u32, Error>::from_der(bytes)
            .map_err(|_unused| Err::Error(X509Error::InvalidVersion))?;
        Ok((input, X509Version { version: o1 }))
    }
}

/// A generic attribute type and value.
#[derive(Drop, Debug, PartialEq)]
pub struct AttributeTypeAndValue {
    attr_type: Oid,
    attr_value: Any // ANY -- DEFINED BY AttributeType
}

#[generate_trait]
pub impl AttributeTypeAndValueImpl of AttributeTypeAndValueTrait {
    /// Builds a new `AttributeTypeAndValue`
    #[inline]
    const fn new(attr_type: Oid, attr_value: Any) -> AttributeTypeAndValue {
        AttributeTypeAndValue { attr_type, attr_value }
    }

    /// Returns the attribute value, as `ANY`
    #[inline]
    const fn attr_value(self: @AttributeTypeAndValue) -> @Any {
        self.attr_value
    }
}

// AttributeTypeAndValue   ::= SEQUENCE {
//     type    AttributeType,
//     value   AttributeValue }
pub impl AttributeTypeAndValueFromDer of FromDer<AttributeTypeAndValue, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<AttributeTypeAndValue> {
        parse_der_sequence_defined_g(
            |i, _hdr, _consumed| -> IResult<@Span<u8>, AttributeTypeAndValue, X509Error> {
                let (i, attr_type) = FromDer::<Oid, Error>::from_der(i)
                    .map_err(|err| err.map(|_unused| X509Error::InvalidX509Name))?;
                let (i, attr_value) = parse_attribute_value(i)
                    .map_err(|err| err.map(|_unused| X509Error::InvalidX509Name))?;
                let attr = AttributeTypeAndValueTrait::new(attr_type, attr_value);
                Ok((i, attr))
            },
            bytes,
        )
    }
}

// AttributeValue          ::= ANY -- DEFINED BY AttributeType
#[inline]
fn parse_attribute_value(i: @Span<u8>) -> ParseResult<Any, Error> {
    alt((|i: @Span<u8>| FromDer::<Any>::from_der(i), |i: @Span<u8>| parse_malformed_string(i)), i)
}

fn parse_malformed_string(i: @Span<u8>) -> ParseResult<Any, Error> {
    panic!("TODO: parse_malformed_string")
}

/// A Relative Distinguished Name element.
#[derive(Drop, Debug, PartialEq)]
pub struct RelativeDistinguishedName {
    set: Array<AttributeTypeAndValue>,
}

pub impl RelativeDistinguishedNameFromDer of FromDer<RelativeDistinguishedName, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<RelativeDistinguishedName> {
        parse_der_set_defined_g(
            |i, _unused| -> IResult<@Span<u8>, RelativeDistinguishedName, X509Error> {
                let (i, set) = many1(
                    |i: @Span<u8>| {
                        complete(
                            |i: @Span<u8>| {
                                FromDer::<AttributeTypeAndValue>::from_der(i)
                            }, i,
                        )
                    },
                    i,
                )?;
                let rdn = RelativeDistinguishedName { set };
                Ok((i, rdn))
            },
            bytes,
        )
    }
}

/// Algorithm identifier
#[derive(Drop, Debug)]
pub struct AlgorithmIdentifier {
    pub algorithm: Oid,
    pub parameters: Option<Any>,
}

#[derive(Drop, Debug)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
    /// A raw unparsed PKIX, ASN.1 DER form (see RFC 5280, Section 4.1).
    ///
    /// Note: use the [`Self::parsed()`] function to parse this object.
    pub raw: Span<u8>,
}

impl SubjectPublicKeyInfoFromDer of FromDer<SubjectPublicKeyInfo, X509Error> {
    /// Parse the SubjectPublicKeyInfo struct portion of a DER-encoded X.509 Certificate
    fn from_der(bytes: @Span<u8>) -> X509Result<SubjectPublicKeyInfo> {
        let start_i = bytes;
        parse_der_sequence_defined_g(
            |i, _hdr, consumed| -> IResult<@Span<u8>, SubjectPublicKeyInfo, X509Error> {
                let (i, algorithm) = FromDer::<AlgorithmIdentifier>::from_der(i)?;
                let (i, subject_public_key) = FromDer::<BitString, X509Error>::from_der(i)
                    .or(Result::Err(nom::Err::Error(X509Error::InvalidSPKI)))?;
                let raw = start_i.slice(0, consumed);
                let spki = SubjectPublicKeyInfo { algorithm, subject_public_key, raw };
                Ok((i, spki))
            },
            bytes,
        )
    }
}

pub impl AlgorithmIdentifierTagged of Tagged<AlgorithmIdentifier> {
    const TAG: Tag = TAG_SEQUENCE;
}

// CAIRO: Manually implementing the code generated by the `DerSequence` macro.
pub impl AlgorithmIdentifierFromDer of FromDer<AlgorithmIdentifier, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<AlgorithmIdentifier> {
        let (rem, any) = FromDer::<Any>::from_der(bytes).map_err(|err| ErrTrait::convert(err))?;
        any.header.assert_tag(AlgorithmIdentifierTagged::TAG).map_err(|e| Err::Error(e.into()))?;
        let i = any.data;
        let (i, algorithm) = FromDer::<Oid, Error>::from_der(i)
            .map_err(|err| err.map(|_unused| X509Error::InvalidAlgorithmIdentifier))?;
        let (_i, parameters) = FromDer::<Option<Any>>::from_der(i)
            .map_err(|err| ErrTrait::convert(err))?;
        Ok((rem, AlgorithmIdentifier { algorithm, parameters }))
    }
}

/// X.509 Name (as used in `Issuer` and `Subject` fields).
#[derive(Drop, Debug, PartialEq)]
pub struct X509Name {
    pub(crate) rdn_seq: Array<RelativeDistinguishedName>,
    pub(crate) raw: @Span<u8>,
}

#[generate_trait]
pub impl X509NameImpl of X509NameTrait {
    // CAIRO: Extra function for finding attribute without external iteration.
    fn find_attribute_by_oid(self: @X509Name, oid: Oid) -> Option<@AttributeTypeAndValue> {
        let mut rdn_iter = self.rdn_seq.span();

        // Weird structure as compiler panics when returning from a loop
        loop {
            match rdn_iter.pop_front() {
                Some(rdn) => {
                    let mut attr_iter = rdn.set.span();

                    let found = loop {
                        match attr_iter.pop_front() {
                            Some(attr) => { if attr.attr_type == @oid {
                                break Some(attr);
                            } },
                            None => { break None; },
                        }
                    };

                    if let Some(found) = found {
                        break Some(found);
                    }
                },
                None => { break None; },
            }
        }
    }
}

pub impl X509NameFromDer of FromDer<X509Name, X509Error> {
    /// Parse the X.501 type Name, used for ex in issuer and subject of a X.509 certificate.
    fn from_der(bytes: @Span<u8>) -> X509Result<X509Name> {
        let start_i = bytes.clone();
        parse_der_sequence_defined_g::<
            _, _, X509Error,
        >(
            |i, _hdr, consumed| -> IResult<@Span<u8>, X509Name, X509Error> {
                let (i, rdn_seq) = many0(
                    |i: @Span<u8>| {
                        complete(
                            |i: @Span<u8>| {
                                FromDer::<RelativeDistinguishedName>::from_der(i)
                            }, i,
                        )
                    },
                    i,
                )?;

                // CAIRO: Rewrote `.offset()` as it's impossible to implement in Cairo.
                let len = consumed;

                let name = X509Name { rdn_seq, raw: @start_i.slice(0, len) };
                Ok((i, name))
            },
            bytes,
        )
    }
}

pub(crate) fn parse_signature_value(i: @Span<u8>) -> X509Result<BitString> {
    FromDer::<BitString, Error>::from_der(i)
        .or(Result::Err(Err::Error(X509Error::InvalidSignatureValue)))
}

pub(crate) fn parse_serial(i: @Span<u8>) -> X509Result<(@Span<u8>, u256)> {
    let (rem, any) = FromBer::<Any>::from_ber(i)
        .map_err(|_unused| X509Error::InvalidSerial.into())?;
    // RFC 5280 4.1.2.2: "The serial number MUST be a positive integer"
    // however, many CAs do not respect this and send integers with MSB set,
    // so we do not use `as_biguint()`
    any.tag().assert_eq(TAG_INTEGER).map_err(|_unused| X509Error::InvalidSerial.into())?;
    let slice = any.data;
    let big = U256FromBytesBe::from_be_byte_span(slice);
    Ok((rem, (slice, big)))
}
