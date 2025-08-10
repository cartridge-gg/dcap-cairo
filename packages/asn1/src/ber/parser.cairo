use core::num::traits::WrappingMul;
use nom::bytes::streaming::take;
use nom::{Err, NeededImpl};
use crate::error::*;
use crate::header::*;
use crate::{FromBer, Length, TAG_ENDOFCONTENT};

/// Default maximum recursion limit
pub const MAX_RECURSION: usize = 50;

pub trait GetObjectContent {
    /// Return the raw content (bytes) of the next ASN.1 encoded object
    ///
    /// Note: if using BER and length is indefinite, terminating End-Of-Content is NOT included
    fn get_object_content(
        i: @Span<u8>, hdr: @Header, max_depth: usize,
    ) -> ParseResult<@Span<u8>, Error>;
}

pub impl BerParserGetObjectContent of GetObjectContent {
    fn get_object_content(
        i: @Span<u8>, hdr: @Header, max_depth: usize,
    ) -> ParseResult<@Span<u8>, Error> {
        let start_i = i;
        let (i, _) = ber_skip_object_content(i, hdr, max_depth)?;

        // CAIRO: Rewrote `.offset()` as it's impossible to implement in Cairo.
        let len = start_i.len() - i.len();

        // CAIRO: Rewrote `.split_at()` as it's impossible to implement in Cairo.
        let content = start_i.slice(0, len);
        let i = start_i.slice(len, start_i.len() - len);

        // if len is indefinite, there are 2 extra bytes for EOC
        if *hdr.length == Length::Indefinite {
            let len = content.len();
            assert!(len >= 2);
            Ok((@i, @content.slice(0, content.len() - 2)))
        } else {
            Ok((@i, @content))
        }
    }
}

pub impl DerParserGetObjectContent of GetObjectContent {
    fn get_object_content(
        i: @Span<u8>, hdr: @Header, max_depth: usize,
    ) -> ParseResult<@Span<u8>, Error> {
        match hdr.length {
            Length::Definite(l) => take(*l, i),
            Length::Indefinite => Result::Err(
                Err::Error(Error::DerConstraintFailed(DerConstraint::IndefiniteLength)),
            ),
        }
    }
}

/// Skip object content, and return true if object was End-Of-Content.
fn ber_skip_object_content(
    i: @Span<u8>, hdr: @Header, max_depth: usize,
) -> ParseResult<bool, Error> {
    if max_depth == 0 {
        return Result::Err(Err::Error(Error::BerMaxDepth));
    }
    match hdr.length {
        Length::Definite(l) => {
            if *l == 0 && *hdr.tag == TAG_ENDOFCONTENT {
                return Ok((i, true));
            }
            let (i, _) = take(*l, i)?;
            Ok((i, false))
        },
        Length::Indefinite => {
            hdr.assert_constructed().map_err(|err| err.into())?;
            // read objects until EndOfContent (00 00)
            // this is recursive
            let mut i = i;
            loop {
                let (i2, header2) = FromBer::<Header>::from_ber(i)?;
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

/// Try to parse input bytes as u64
#[inline]
pub(crate) fn bytes_to_u64(s: @Span<u8>) -> Result<u64, Error> {
    let mut u: u64 = 0;
    for c in s {
        if u & 0xff00_0000_0000_0000 != 0 {
            return Result::Err(Error::IntegerTooLarge);
        }
        u = u.wrapping_mul(0b1_0000_0000);
        u = u | Into::<_, u64>::into(*c);
    }
    Ok(u)
}

pub(crate) fn parse_identifier(i: @Span<u8>) -> ParseResult<(u8, u8, u32, @Span<u8>), Error> {
    if i.is_empty() {
        Result::Err(Err::Incomplete(NeededImpl::new(1)))
    } else {
        let a = *i[0] / 0b0100_0000;
        let b = if *i[0] & 0b0010_0000 != 0 {
            1_u8
        } else {
            0_u8
        };
        let mut c = Into::<_, u32>::into(*i[0] & 0b0001_1111);

        let mut tag_byte_count = 1;

        if c == 0x1f {
            c = 0;

            loop {
                // Make sure we don't read past the end of our data.
                if tag_byte_count >= i.len() {
                    return Result::Err(Err::<Error>::Error(Error::InvalidTag));
                }

                // With tag defined as u32 the most we can fit in is four tag bytes.
                // (X.690 doesn't actually specify maximum tag width.)
                if tag_byte_count > 5 {
                    return Result::Err(Err::<Error>::Error(Error::InvalidTag));
                }

                c = (c.wrapping_mul(0x1000_0000))
                    | (Into::<_, u32>::into(*i[tag_byte_count]) & 0x7f);
                let done = *i[tag_byte_count] & 0x80 == 0;
                tag_byte_count += 1;
                if done {
                    break;
                }
            }
        }

        let raw_tag = @i.slice(0, tag_byte_count);
        let rem = @i.slice(tag_byte_count, i.len() - tag_byte_count);

        Ok((rem, (a, b, c, raw_tag)))
    }
}

/// Return the MSB and the rest of the first byte, or an error
pub(crate) fn parse_ber_length_byte(i: @Span<u8>) -> ParseResult<(u8, u8), Error> {
    if i.is_empty() {
        Result::Err(Err::Incomplete(NeededImpl::new(1)))
    } else {
        let a = *i[0] / 0b1000_0000;
        let b = *i[0] & 0b0111_1111;
        Ok((@i.slice(1, i.len() - 1), (a, b)))
    }
}
