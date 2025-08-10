use nom::{Err, ErrImpl, ErrTrait};
use crate::*;

/// Helper object to parse TAGGED OPTIONAL types (explicit or implicit).
#[derive(Drop, Debug)]
pub struct OptTaggedParser {
    /// The expected class for the object to parse
    pub class: Class,
    /// The expected tag for the object to parse
    pub tag: Tag,
}

#[generate_trait]
pub impl OptTaggedParserImpl of OptTaggedParserTrait {
    /// Build a new `OptTaggedParser` object.
    fn new(class: Class, tag: Tag) -> OptTaggedParser {
        OptTaggedParser { class, tag }
    }

    /// Parse input as DER, and apply the provided function to parse object.
    fn parse_der<
        T,
        E,
        F,
        impl Fn: core::ops::Fn<F, (Header, @Span<u8>)>[Output: ParseResult<T, E>],
        +Drop<T>,
        +Drop<E>,
        +Drop<F>,
        +Into<Error, E>,
    >(
        self: OptTaggedParser, bytes: @Span<u8>, f: F,
    ) -> ParseResult<Option<T>, E> {
        if bytes.is_empty() {
            return Ok((bytes, None));
        }
        // CAIRO: `.map_err(|err| ErrTrait::convert(err))` causes a compiler panic.
        let (rem, any) = match FromDer::<Any>::from_der(bytes) {
            Ok(value) => value,
            // THIS STILL PANICS!
            Result::Err(err) => { return Result::Err(ErrTrait::convert(err)); },
        };
        if any.tag() != @self.tag {
            return Ok((bytes, None));
        }
        if any.class() != @self.class {
            return Result::Err(
                Err::Error(
                    Error::UnexpectedClass(
                        UnexpectedClass { expected: Some(self.class), actual: *any.class() },
                    )
                        .into(),
                ),
            );
        }
        let Any { header, data } = any;
        let (_, res) = f(header, data)?;
        Ok((rem, Some(res)))
    }
}

impl U32IntoOptTaggedParser of Into<u32, OptTaggedParser> {
    fn into(self: u32) -> OptTaggedParser {
        OptTaggedParserImpl::new(Class::ContextSpecific, Tag { tag: self })
    }
}

/// A helper object to parse `[ n ] IMPLICIT T OPTIONAL`.
pub type OptTaggedImplicit<T, E, const TAG: u32> = Option<TaggedImplicit<T, E, TAG>>;
