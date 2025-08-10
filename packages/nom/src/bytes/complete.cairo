use crate::error::{ErrorKind, ParseError};
use crate::internal::{Err, IResult};
use crate::traits::{InputIter, InputTake};

/// Returns an input slice containing the first N input elements (Input[..N]).
pub fn take<
    C,
    Input,
    Error,
    +InputIter<Input>,
    +InputTake<Input>,
    +Drop<Input>,
    +Copy<Input>,
    +Drop<C>,
    +Into<C, usize>,
    +Drop<Error>,
    +ParseError<Error, Input>,
>(
    count: C, input: Input,
) -> IResult<Input, Input, Error> {
    let c = count.into();
    let lambda = |i: Input| -> IResult<Input, Input, Error> {
        match i.slice_index(c) {
            Result::Err(_needed) => Result::Err(
                Err::<Error>::Error(ParseError::<Error, Input>::from_error_kind(i, ErrorKind::Eof)),
            ),
            Ok(index) => Ok(i.take_split(index)),
        }
    };

    // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
    lambda(input)
}
