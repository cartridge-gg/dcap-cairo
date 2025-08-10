use asn1::FromBer;
use nom::Err;
use nom::bytes::streaming::take;
use crate::ber::*;
use crate::error::*;

/// Default maximum recursion limit
pub const MAX_RECURSION: usize = 50;

/// Default maximum object size (2^32)
pub const MAX_OBJECT_SIZE: usize = 4_294_967_295;

/// Skip object content, and return true if object was End-Of-Content
pub(crate) fn ber_skip_object_content(
    i: @Span<u8>, hdr: @Header, max_depth: usize,
) -> BerResult<bool> {
    if max_depth == 0 {
        return Result::Err(Err::Error(BerError::BerMaxDepth));
    }
    match hdr.length() {
        Length::Definite(l) => {
            if *l == 0 && *hdr.tag() == TAG_ENDOFCONTENT {
                return Ok((i, true));
            }
            let (i, _) = take(*l, i)?;
            Ok((i, false))
        },
        Length::Indefinite => {
            if hdr.is_primitive() {
                return Result::Err(Err::Error(BerError::ConstructExpected));
            }
            // read objects until EndOfContent (00 00)
            // this is recursive
            let mut i = i;
            loop {
                let (i2, header2) = ber_read_element_header(i)?;
                let (i3, eoc) = ber_skip_object_content(i2, @header2, max_depth - 1)?;
                if eoc {
                    // return false, since top object was not EndOfContent
                    return Ok((i3, false));
                }
                i = i3;
            }
        },
    }
}

/// Read object raw content (bytes)
pub(crate) fn ber_get_object_content(
    i: @Span<u8>, hdr: @Header, max_depth: usize,
) -> BerResult<@Span<u8>> {
    let start_i = i;
    let (i, _) = ber_skip_object_content(i, hdr, max_depth)?;

    // CAIRO: Rewrote `.offset()` as it's impossible to implement in Cairo.
    let len = start_i.len() - i.len();

    let content = start_i.slice(0, len);
    let i = start_i.slice(len, start_i.len() - len);

    // if len is indefinite, there are 2 extra bytes for EOC
    if *hdr.length() == Length::Indefinite {
        let len = content.len();
        assert!(len >= 2);
        Ok((@i, @content.slice(0, len - 2)))
    } else {
        Ok((@i, @content))
    }
}

/// Read an object header
#[inline]
pub fn ber_read_element_header(i: @Span<u8>) -> BerResult<Header> {
    FromBer::<Header>::from_ber(i)
}

#[inline]
pub fn ber_read_element_content_as(
    i: @Span<u8>, tag: Tag, length: Length, constructed: bool, max_depth: usize,
) -> BerResult<BerObjectContent> {
    try_read_berobjectcontent_as(i, tag, length, constructed, max_depth)
}

/// Parse a BER object, expecting a value with specified tag
///
/// The object is parsed recursively, with a maximum depth of `MAX_RECURSION`.
pub fn parse_ber_with_tag<T, +Into<T, Tag>, +Drop<T>>(
    i: @Span<u8>, tag: T,
) -> BerResult<BerObject> {
    let tag = Into::<T, Tag>::into(tag);
    let (i, hdr) = ber_read_element_header(i)?;
    hdr.assert_tag(tag).map_err(|err| err.into())?;
    let (i, content) = ber_read_element_content_as(
        i, *hdr.tag(), *hdr.length(), hdr.is_constructed(), MAX_RECURSION,
    )?;
    Ok((i, BerObjectTrait::from_header_and_content(hdr, content)))
}

/// Read a boolean value.
#[inline]
pub fn parse_ber_bool(i: @Span<u8>) -> BerResult<BerObject> {
    parse_ber_with_tag(i, TAG_BOOLEAN)
}
