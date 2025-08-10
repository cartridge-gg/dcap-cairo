use crate::*;

pub impl OptionTaggedFromDer<T, +FromDer<T, Error>, +Tagged<T>> of FromDer<Option<T>, Error> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<Option<T>, Error> {
        if bytes.is_empty() {
            return Ok((bytes, None));
        }
        if let Ok((_, header)) = FromDer::<Header>::from_der(bytes) {
            if Tagged::<T>::TAG != header.tag {
                // not the expected tag, early return
                return Ok((bytes, None));
            }
        }
        match FromDer::<T, Error>::from_der(bytes) {
            Ok((rem, t)) => Ok((rem, Some(t))),
            Result::Err(e) => Result::Err(e),
        }
    }
}

pub impl OptionAnyFromDer of FromDer<Option<Any>, Error> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<Option<Any>, Error> {
        if bytes.is_empty() {
            return Ok((bytes, None));
        }
        match FromDer::<Any>::from_der(bytes) {
            Ok((rem, t)) => Ok((rem, Some(t))),
            Result::Err(e) => Result::Err(e),
        }
    }
}
