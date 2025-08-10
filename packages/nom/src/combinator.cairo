use crate::error::{ErrorKind, ParseError};
use crate::internal::*;

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Maps a function on the result of a parser.
pub fn map<
    O1,
    O2,
    E,
    F,
    G,
    impl FnF: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, O1, E>],
    impl FnG: core::ops::Fn<G, (O1,)>[Output: O2],
    +Drop<O1>,
    +Drop<F>,
    +Drop<G>,
>(
    parser: F, f: G, input: @Span<u8>,
) -> IResult<@Span<u8>, O2, E> {
    let lambda = |input: @Span<u8>| -> IResult<@Span<u8>, O2, E> {
        let (input, o1) = parser(input)?;
        Ok((input, f(o1)))
    };

    lambda(input)
}

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Optional parser, will return `None` on [`Err::Error`].
pub fn opt<
    O,
    E,
    F,
    impl Fn: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<E>,
    +Drop<F>,
    +ParseError<E, @Span<u8>>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, Option<O>, E> {
    let lambda = |input: @Span<u8>| -> IResult<@Span<u8>, Option<O>, E> {
        let rest = f(input);
        match rest {
            Ok((i, o)) => Ok((i, Some(o))),
            Result::Err(err) => match @err {
                Err::Error(_) => Ok((input, None)),
                _ => Result::Err(err),
            },
        }
    };

    lambda(input)
}

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Transforms Incomplete into `Error`.
pub fn complete<
    O,
    E,
    F,
    impl Fn: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<E>,
    +Drop<F>,
    +ParseError<E, @Span<u8>>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, O, E> {
    let lambda = |input: @Span<u8>| -> IResult<@Span<u8>, O, E> {
        let i = input.clone();
        let rest = f(input);
        match @rest {
            Result::Err(err) => match err {
                Err::Incomplete(_) => Result::Err(
                    Err::Error(ParseError::<E, _>::from_error_kind(@i, ErrorKind::Complete)),
                ),
                _ => rest,
            },
            _ => rest,
        }
    };

    lambda(input)
}

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Succeeds if all the input has been consumed by its child parser.
pub fn all_consuming<
    O,
    E,
    F,
    impl Fn: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<E>,
    +Drop<F>,
    +ParseError<E, @Span<u8>>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, O, E> {
    let lambda = |input: @Span<u8>| -> IResult<@Span<u8>, O, E> {
        let (input, res) = f(input)?;
        if input.len() == 0 {
            Ok((input, res))
        } else {
            Result::Err(Err::Error(ParseError::<E, _>::from_error_kind(input, ErrorKind::Eof)))
        }
    };

    lambda(input)
}

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Transforms an [`Err::Error`] (recoverable) to [`Err::Failure`] (unrecoverable)
///
/// This commits the parse result, preventing alternative branch paths like with
/// [`nom::branch::alt`][crate::branch::alt].
pub fn cut<
    O,
    E,
    F,
    impl Fn: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<E>,
    +Drop<F>,
    +Clone<E>,
    +ParseError<E, @Span<u8>>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, O, E> {
    let lambda = |input: @Span<u8>| -> IResult<@Span<u8>, O, E> {
        match f(input) {
            Result::Err(err) => match @err {
                Err::Error(e) => Result::Err(Err::Failure(e.clone())),
                _ => Result::Err(err),
            },
            Ok(value) => Ok(value),
        }
    };

    lambda(input)
}
