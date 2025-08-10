use crate::error::{ErrorKind, ParseError};
use crate::internal::{Err, IResult};

/// Helper trait for the [alt()] combinator.
///
/// This trait is implemented for tuples of up to 21 elements
pub trait Alt<SELF, I, O, E> {
    /// Tests each parser in the tuple and returns the result of the first one that succeeds
    fn choice(self: SELF, input: I) -> IResult<I, O, E>;
}

pub fn alt<
    I,
    O,
    E,
    List,
    +Drop<I>,
    +Drop<O>,
    +Drop<E>,
    +Drop<List>,
    +Clone<I>,
    // CAIRO: Added `Clone` constraint as Cairo doesn't support matching with a fallback branch.
    +Clone<E>,
    +ParseError<E, I>,
    +Alt<List, I, O, E>,
>(
    l: List, input: I,
) -> IResult<I, O, E> {
    l.choice(input)
}

impl AltAB<
    Input,
    Output,
    Error,
    A,
    B,
    impl FnA: core::ops::Fn<A, (Input,)>[Output: IResult<Input, Output, Error>],
    impl FnB: core::ops::Fn<B, (Input,)>[Output: IResult<Input, Output, Error>],
    +Drop<Input>,
    +Drop<Output>,
    +Drop<Error>,
    +Drop<A>,
    +Drop<B>,
    +Clone<Input>,
    // CAIRO: Added `Clone` constraint as Cairo doesn't support matching with a fallback branch.
    +Clone<Error>,
    +ParseError<Error, Input>,
> of Alt<(A, B), Input, Output, Error> {
    fn choice(self: (A, B), input: Input) -> IResult<Input, Output, Error> {
        let (self0, self1) = self;
        let res = self0(input.clone());
        match @res {
            Result::Err(e) => match e {
                Err::Error(_) => {
                    let res = self1(input.clone());
                    match @res {
                        Result::Err(e) => match e {
                            Err::Error(e) => Result::Err(
                                Err::Error(
                                    ParseError::<Error>::append(input, ErrorKind::Alt, e.clone()),
                                ),
                            ),
                            _ => res,
                        },
                        _ => res,
                    }
                },
                _ => res,
            },
            _ => res,
        }
    }
}
