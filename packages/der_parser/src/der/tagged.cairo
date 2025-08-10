use asn1::{Class, Header, HeaderTrait, Tag, UnexpectedClass};
use nom::error::ParseError;
use nom::{Err, IResult};
use crate::ber::{BerObject, BerObjectTrait, MAX_RECURSION};
use crate::der::*;
use crate::error::*;

/// Read a TAGGED EXPLICIT value (generic version)
pub fn parse_der_tagged_explicit_g<
    T,
    Output,
    F,
    E,
    impl Fn: core::ops::Fn<F, (@Span<u8>, Header)>[Output: IResult<@Span<u8>, Output, E>],
    +Drop<T>,
    +Drop<Output>,
    +Drop<F>,
    +Drop<E>,
    +Into<T, Tag>,
    +ParseError<E, @Span<u8>>,
    +Into<BerError, E>,
>(
    tag: T, f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, Output, E> {
    let tag: Tag = tag.into();
    parse_der_container(
        |i, hdr, _consumed| -> IResult<@Span<u8>, Output, E> {
            if hdr.class() == @Class::Universal {
                return Result::Err(
                    Err::Error(
                        BerError::UnexpectedClass(
                            UnexpectedClass { expected: None, actual: *hdr.class() },
                        )
                            .into(),
                    ),
                );
            }
            hdr.assert_tag(tag).map_err(|e| Err::Error(e.into()))?;
            // X.690 8.14.2: if implicit tagging was not used, the encoding shall be constructed
            if !hdr.is_constructed() {
                return Result::Err(Err::Error(BerError::ConstructExpected.into()));
            }
            f(i, hdr)
            // trailing bytes are ignored
        },
        input,
    )
}

/// Read a TAGGED IMPLICIT value (combinator)
///
/// Parse a TAGGED IMPLICIT value, given the expected tag, and the content parsing function.
///
/// The built object will use the original header (and tag), so the content may not match the tag
/// value.
///
/// For a generic version (different output and error types), see
/// [parse_der_tagged_implicit_g](fn.parse_der_tagged_implicit_g.html).
pub fn parse_der_tagged_implicit<
    T,
    F,
    impl Fn: core::ops::Fn<F, (@Span<u8>, @Header, usize)>[Output: BerResult<DerObjectContent>],
    +Drop<T>,
    +Drop<F>,
    +Into<T, Tag>,
>(
    tag: T, f: F, input: @Span<u8>,
) -> BerResult<BerObject> {
    let tag: Tag = tag.into();
    parse_der_tagged_implicit_g(
        tag,
        |i, hdr, depth| -> IResult<@Span<u8>, BerObject, BerError> {
            let (rem, content) = f(i, @hdr, depth)?;
            // trailing bytes are ignored
            let obj = BerObjectTrait::from_header_and_content(hdr, content);
            Ok((rem, obj))
        },
        input,
    )
}

/// Read a TAGGED IMPLICIT value (generic version)
pub fn parse_der_tagged_implicit_g<
    T,
    Output,
    F,
    E,
    impl Fn: core::ops::Fn<F, (@Span<u8>, Header, usize)>[Output: IResult<@Span<u8>, Output, E>],
    +Drop<T>,
    +Drop<Output>,
    +Drop<F>,
    +Drop<E>,
    +Into<T, Tag>,
    +ParseError<E, @Span<u8>>,
    +Into<BerError, E>,
>(
    tag: T, f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, Output, E> {
    let tag: Tag = tag.into();
    parse_der_container(
        |i, hdr, _consumed| -> IResult<@Span<u8>, Output, E> {
            hdr.assert_tag(tag).map_err(|e| Err::Error(e.into()))?;
            // XXX MAX_RECURSION should not be used, it resets the depth counter
            f(i, hdr, MAX_RECURSION)
            // trailing bytes are ignored
        },
        input,
    )
}
