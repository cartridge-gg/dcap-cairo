use asn1::{
    FromDerViaAny, Header, HeaderFromDer, HeaderTrait, Length, LengthTrait, TAG_BITSTRING,
    TAG_BMPSTRING, TAG_BOOLEAN, TAG_GENERALIZEDTIME, TAG_GENERALSTRING, TAG_GRAPHICSTRING,
    TAG_IA5STRING, TAG_INTEGER, TAG_NUMERICSTRING, TAG_OBJECTDESCRIPTOR, TAG_PRINTABLESTRING,
    TAG_SEQUENCE, TAG_T61STRING, TAG_UNIVERSALSTRING, TAG_UTCTIME, TAG_UTF8STRING,
    TAG_VIDEOTEXSTRING, TAG_VISIBLESTRING, U32CheckDerConstraints,
};
use nom::{Err, NeededTrait};
use crate::ber::{BerObjectTrait, MAX_RECURSION, ber_read_element_content_as};
use crate::der::*;
use crate::error::*;

/// Parse a DER object, expecting a value with specified tag
///
/// The object is parsed recursively, with a maximum depth of `MAX_RECURSION`.
pub fn parse_der_with_tag<T, +Into<T, Tag>>(i: @Span<u8>, tag: T) -> DerResult {
    let tag = Into::<T, Tag>::into(tag);
    let (i, hdr) = der_read_element_header(i)?;
    hdr.assert_tag(tag).map_err(|err| err.into())?;
    let (i, content) = der_read_element_content_as(
        i, *hdr.tag(), *hdr.length(), hdr.is_constructed(), MAX_RECURSION,
    )?;
    Ok((i, BerObjectTrait::from_header_and_content(hdr, content)))
}

/// Parse a sequence of DER elements.
#[inline]
pub fn parse_der_sequence(i: @Span<u8>) -> DerResult {
    parse_der_with_tag(i, TAG_SEQUENCE)
}

/// Parse DER object and try to decode it as a 32-bits unsigned integer
///
/// Return `IntegerTooLarge` if object is an integer, but can not be represented in the target
/// integer type.
pub fn parse_der_u32(i: @Span<u8>) -> BerResult<u32> {
    FromDerViaAny::<u32>::from_der(i)
}

/// Parse the next bytes as the content of a DER object (combinator, header reference)
///
/// Content type is *not* checked to match tag, caller is responsible of providing the correct tag
///
/// Caller is also responsible to check if parsing function consumed the expected number of
/// bytes (`header.len`).
///
/// This function differs from [`parse_der_content2`](fn.parse_der_content2.html) because it passes
/// the BER object header by reference (required for ex. by `parse_der_implicit`).
///
/// The arguments of the parse function are: `(input, ber_object_header, max_recursion)`.
pub fn parse_der_content(
    tag: Tag, input: @Span<u8>, header: Header, max_depth: usize,
) -> BerResult<DerObjectContent> {
    panic!("TODO: parse_der_content")
}

/// Parse the next bytes as the content of a DER object.
///
/// Content type is *not* checked, caller is responsible of providing the correct tag
pub fn der_read_element_content_as(
    i: @Span<u8>, tag: Tag, length: Length, constructed: bool, max_depth: usize,
) -> BerResult<DerObjectContent> {
    // Indefinite lengths are not allowed in DER (X.690 section 10.1)
    let l = length.definite().map_err(|err| err.into())?;
    if i.len() < l {
        return Result::Err(Err::Incomplete(NeededTrait::new(l)));
    }

    if tag == TAG_BOOLEAN {
        panic!("TODO: der_read_element_content_as - tag = branch 1");
    } else if tag == TAG_BITSTRING {
        panic!("TODO: der_read_element_content_as - tag = branch 2");
    } else if tag == TAG_INTEGER {
        panic!("TODO: der_read_element_content_as - tag = branch 3");
    } else if tag == TAG_NUMERICSTRING
        || tag == TAG_VISIBLESTRING
        || tag == TAG_PRINTABLESTRING
        || tag == TAG_IA5STRING
        || tag == TAG_UTF8STRING
        || tag == TAG_T61STRING
        || tag == TAG_VIDEOTEXSTRING
        || tag == TAG_BMPSTRING
        || tag == TAG_UNIVERSALSTRING
        || tag == TAG_OBJECTDESCRIPTOR
        || tag == TAG_GRAPHICSTRING
        || tag == TAG_GENERALSTRING {
        panic!("TODO: der_read_element_content_as - tag = branch 4");
    } else if tag == TAG_UTCTIME || tag == TAG_GENERALIZEDTIME {
        panic!("TODO: der_read_element_content_as - tag = branch 5");
    }
    ber_read_element_content_as(i, tag, length, constructed, max_depth)
}

/// Read an object header (DER)
#[inline]
pub fn der_read_element_header(i: @Span<u8>) -> BerResult<Header> {
    HeaderFromDer::from_der(i)
}
