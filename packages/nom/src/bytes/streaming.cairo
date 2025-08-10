use crate::error::ParseError;
use crate::internal::{Err, IResult};
use crate::traits::{InputIter, InputTake};

/// Returns an input slice containing the first N input elements (Input[..N]).
///
/// # Streaming Specific
///
/// *Streaming version* if the input has less than N elements, `take` will
/// return a `Err::Incomplete(Needed::new(M))` where M is the number of
/// additional bytes the parser would need to succeed.
///
/// It is well defined for `&[u8]` as the number of elements is the byte size,
/// but for types like `&str`, we cannot know how many bytes correspond for
/// the next few chars, so the result will be `Err::Incomplete(Needed::Unknown)`
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
            Result::Err(i) => Result::Err(Err::Incomplete(i)),
            Ok(index) => Ok(i.take_split(index)),
        }
    };

    // CAIRO: Rewrote the functional `impl Fn` return to be invoked immediately.
    lambda(input)
}
