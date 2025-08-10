use crate::error::{ErrorKind, ParseError};
use crate::internal::{Err, IResult};

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Repeats the embedded parser, gathering the results in a `Vec`.
pub fn many0<
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
) -> IResult<@Span<u8>, Array<O>, E> {
    let lambda = |i: @Span<u8>| -> IResult<@Span<u8>, Array<O>, E> {
        let mut i = i;
        let mut acc = array![];
        let result = loop {
            let len = i.len();
            match f(i) {
                // CAIRO: Rewrote conditions as Cairo doesn't support inner patterns.
                Result::Err(e) => {
                    break match @e {
                        Err::Error(_) => Ok(i),
                        _ => Result::Err(e),
                    };
                },
                Ok((
                    i1, o,
                )) => {
                    // infinite loop check: the parser must always consume
                    if i1.len() == len {
                        break Result::Err(
                            Err::Error(ParseError::<E, _>::from_error_kind(i, ErrorKind::Many0)),
                        );
                    }
                    i = i1;
                    acc.append(o);
                },
            }
        };

        // CAIRO: Rewrote to only map `acc` in here as the Cairo compiler would raise a false
        // positive for use after move.
        match result {
            Ok(i) => Ok((i, acc)),
            Result::Err(e) => Result::Err(e),
        }
    };

    // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
    lambda(input)
}

// CAIRO: Replaced `Parser` bound with just `Fn`.
//
/// Runs the embedded parser, gathering the results in a `Vec`.
///
/// This stops on [`Err::Error`] if there is at least one result,  and returns the results that were
/// accumulated. To instead chain an error up, see [`cut`][crate::combinator::cut].
pub fn many1<
    O,
    E,
    F,
    impl Fn: core::ops::Fn<F, (@Span<u8>,)>[Output: IResult<@Span<u8>, O, E>],
    +Drop<O>,
    +Drop<E>,
    +Drop<F>,
    // CAIRO: Added `Clone` constraint as Cairo doesn't support matching with a fallback branch.
    +Clone<E>,
    +ParseError<E, @Span<u8>>,
>(
    f: F, input: @Span<u8>,
) -> IResult<@Span<u8>, Array<O>, E> {
    let lambda = |i: @Span<u8>| -> IResult<@Span<u8>, Array<O>, E> {
        let mut i = i;
        match f(i) {
            Result::Err(e) => match @e {
                Err::Error(err) => Result::Err(
                    Err::Error(ParseError::<E>::append(i, ErrorKind::Many1, err.clone())),
                ),
                _ => Result::Err(e),
            },
            Ok((
                i1, o,
            )) => {
                let mut acc = array![];
                acc.append(o);
                i = i1;

                let result = loop {
                    let len = i.len();
                    match f(i) {
                        Result::Err(e) => {
                            break match @e {
                                Err::Error(_) => Ok(i),
                                _ => Result::Err(e),
                            };
                        },
                        Ok((
                            i1, o,
                        )) => {
                            // infinite loop check: the parser must always consume
                            if i1.len() == len {
                                break Result::Err(
                                    Err::Error(
                                        ParseError::<E>::from_error_kind(i, ErrorKind::Many1),
                                    ),
                                );
                            }

                            i = i1;
                            acc.append(o);
                        },
                    }
                };

                // CAIRO: Rewrote to only map `acc` in here as the Cairo compiler would raise a
                // false positive for use after move.
                match result {
                    Ok(i) => Ok((i, acc)),
                    Result::Err(e) => Result::Err(e),
                }
            },
        }
    };

    // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
    lambda(input)
}
