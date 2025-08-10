use crate::*;

mod optional;

pub use optional::*;

pub(crate) const CONTEXT_SPECIFIC: u8 = 0b10;

/// A type parameter for `IMPLICIT` tagged values.
#[derive(Debug)]
pub enum Implicit {}

/// Helper object for creating `FromBer`/`FromDer` types for TAGGED OPTIONAL types.
///
/// When parsing `ContextSpecific` (the most common class), see [`TaggedExplicit`] and
/// [`TaggedImplicit`] alias types.
#[derive(Drop, Debug)]
pub struct TaggedValue<T, E, TagKind, const CLASS: u8, const TAG: u32> {
    pub(crate) inner: T,
}

#[generate_trait]
pub impl TaggedValueImpl<
    T, E, TagKind, const CLASS: u8, const TAG: u32,
> of TaggedValueTrait<T, E, TagKind, CLASS, TAG> {
    /// Consumes the `TaggedParser`, returning the wrapped value.
    #[inline]
    fn into_inner(self: TaggedValue<T, E, TagKind, CLASS, TAG>) -> T {
        self.inner
    }
}

#[generate_trait]
pub impl TaggedValueImplicitImpl<
    T, E, const CLASS: u8, const TAG: u32,
> of TaggedValueImplicitTrait<T, E, CLASS, TAG> {
    /// Constructs a new `IMPLICIT TaggedParser` with the provided value
    #[inline]
    const fn implicit(inner: T) -> TaggedValue<T, E, Implicit, CLASS, TAG> {
        TaggedValue { inner }
    }
}

pub impl TaggedTagged<
    T, E, TagKind, const CLASS: u8, const TAG: u32,
> of Tagged<TaggedValue<T, E, TagKind, CLASS, TAG>> {
    const TAG: Tag = Tag { tag: TAG };
}
