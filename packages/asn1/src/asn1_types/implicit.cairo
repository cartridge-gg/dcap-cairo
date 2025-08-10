use crate::*;

pub impl TaggedImplicitFromDer<
    T,
    E,
    const CLASS: u8,
    const TAG: u32,
    +Into<Any, Result<T, E>>,
    +Tagged<T>,
    +Into<Error, E>,
    +Drop<E>,
> of FromDer<TaggedValue<T, E, Implicit, CLASS, TAG>, E> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<TaggedValue<T, E, Implicit, CLASS, TAG>, E> {
        let (rem, any) = FromDer::<Any>::from_der(bytes)
            .map_err(|err| nom::ErrTrait::convert(err))?;
        any.tag().assert_eq(Tag { tag: TAG }).map_err(|e| nom::Err::Error(e.into()))?;
        if (*any.class()).into() != CLASS {
            let class = TryInto::<u8, Class>::try_into(CLASS);
            return Result::Err(
                nom::Err::Error(
                    Error::UnexpectedClass(
                        UnexpectedClass { expected: class, actual: *any.class() },
                    )
                        .into(),
                ),
            );
        }
        let any = Any {
            header: Header { tag: Tagged::<T>::TAG, ..any.header.clone() }, data: any.data,
        };
        match Into::<Any, Result<T, E>>::into(any) {
            Ok(inner) => Ok((rem, TaggedValueImplicitImpl::implicit(inner))),
            Result::Err(e) => Result::Err(nom::Err::Error(e)),
        }
    }
}

pub type TaggedImplicit<T, E, const TAG: u32> = TaggedValue<T, E, Implicit, CONTEXT_SPECIFIC, TAG>;
