use crate::{BerParser, DerParser, Error, FromBer, FromDer};

/// An Iterator over binary data, parsing elements of type `T`
///
/// This helps parsing `SEQUENCE OF` items of type `T`. The type of parser
/// (BER/DER) is specified using the generic parameter `F` of this struct.
///
/// Note: the iterator must start on the sequence *contents*, not the sequence itself.
#[derive(Drop, Debug)]
pub struct SequenceIterator<T, F, E> {
    data: @Span<u8>,
    has_error: bool,
}

#[generate_trait]
pub impl SequenceIteratorImpl<T, F, E> of SequenceIteratorTrait<T, F, E> {
    fn new(data: @Span<u8>) -> SequenceIterator<T, F, E> {
        SequenceIterator { data, has_error: false }
    }
}

#[generate_trait]
pub impl SequenceIteratorIterImpl<
    T, F, E, +FromBer<T, E>, +Into<Error, E>,
> of SequenceIteratorIterTrait<T, F, E> {
    fn next(ref self: SequenceIterator<T, F, E>) -> Option<Result<T, E>> {
        if self.has_error || self.data.is_empty() {
            return None;
        }
        match FromBer::<T>::from_ber(self.data) {
            Ok((rem, obj)) => {
                self.data = rem;
                Some(Ok(obj))
            },
            Result::Err(err) => match err {
                nom::Err::Error(e) |
                nom::Err::Failure(e) => {
                    self.has_error = true;
                    Some(Result::Err(e))
                },
                nom::Err::Incomplete(n) => {
                    self.has_error = true;
                    Some(Result::Err(Error::Incomplete(n).into()))
                },
            },
        }
    }
}
