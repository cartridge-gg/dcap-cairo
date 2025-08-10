use asn1::{DerConstraint, Header, HeaderImpl, Length, TAG_SEQUENCE, TAG_SET};
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, complete, cut};
use nom::error::ParseError;
use nom::multi::many0;
use nom::{Err, ErrTrait, IResult};
use crate::der::*;
use crate::error::*;

/// Parse a SEQUENCE OF object (returning a vec).
pub fn parse_der_sequence_of_v<
    T,
    F,
    E,
    impl Fn: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, T, E>],
    +Drop<T>,
    +Drop<F>,
    +Drop<E>,
    +Clone<E>,
    +ParseError<E, @Span<u8>>,
    +Into<BerError, E>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, Array<T>, E> {
    let subparser = |i: @Span<u8>| -> IResult<@Span<u8>, Array<T>, E> {
        all_consuming(
            |i: @Span<u8>| -> IResult<@Span<u8>, Array<T>, E> {
                many0(
                    |i: @Span<u8>| -> IResult<@Span<u8>, T, E> {
                        complete(
                            |i: @Span<u8>| -> IResult<@Span<u8>, T, E> {
                                cut(|i: @Span<u8>| -> IResult<@Span<u8>, T, E> {
                                    f(i)
                                }, i)
                            },
                            i,
                        )
                    },
                    i,
                )
            },
            i,
        )
    };

    parse_der_sequence_defined_g(|data: @Span<u8>, _hdr, _consumed| subparser(data), input)
}

/// Parse a defined SEQUENCE object (generic function).
pub fn parse_der_sequence_defined_g<
    O,
    F,
    E,
    impl Fn: core::ops::Fn<F, (@Span<u8>, Header, usize)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<F>,
    +Drop<E>,
    +ParseError<E, @Span<u8>>,
    +Into<BerError, E>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, O, E> {
    parse_der_container(
        |i, hdr, consumed| -> IResult<@Span<u8>, O, E> {
            hdr.assert_tag(TAG_SEQUENCE).map_err(|e| Err::Error(e.into()))?;
            f(i, hdr, consumed)
        },
        // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
        input,
    )
}

/// Parse a defined SET object (generic version)
pub fn parse_der_set_defined_g<
    O,
    F,
    E,
    impl Fn: core::ops::Fn<F, (@Span<u8>, Header)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<F>,
    +Drop<E>,
    +ParseError<E, @Span<u8>>,
    +Into<BerError, E>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, O, E> {
    parse_der_container(
        |i, hdr, _consumed| -> IResult<@Span<u8>, O, E> {
            hdr.assert_tag(TAG_SET).map_err(|e| Err::Error(e.into()))?;
            f(i, hdr)
        },
        // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
        input,
    )
}

/// Parse a DER object and apply provided function to content.
pub fn parse_der_container<
    O,
    F,
    E,
    impl Fn: core::ops::Fn<F, (@Span<u8>, Header, usize)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<F>,
    +Drop<E>,
    +ParseError<E, @Span<u8>>,
    +Into<BerError, E>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, O, E> {
    let lambda = |i: @Span<u8>| -> IResult<@Span<u8>, O, E> {
        let (i, hdr) = der_read_element_header(i).map_err(|err| ErrTrait::convert(err))?;
        let (i, data) = match hdr.length() {
            Length::Definite(len) => take::<_, _, E>(*len, i)?,
            Length::Indefinite => {
                return Result::Err(
                    Err::Error(
                        BerError::DerConstraintFailed(DerConstraint::IndefiniteLength).into(),
                    ),
                );
            },
        };

        // CAIRO: Trick to work around the fact that `.offset()` is impossible to implement in
        //        Cairo.
        let consumed = input.len() - i.len();
        let (_rest, v) = f(data, hdr, consumed)?;
        Ok((i, v))
    };

    // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
    lambda(input)
}
