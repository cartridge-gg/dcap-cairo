use crate::*;

mod iterator;

pub use iterator::*;

#[derive(Drop, Debug)]
pub struct Sequence {
    /// Serialized DER representation of the sequence content
    pub content: @Span<u8>,
}

pub impl AnyTryIntoSequence of Into<Any, Result<Sequence, Error>> {
    fn into(self: Any) -> Result<Sequence, Error> {
        self.tag().assert_eq(SequenceTagged::TAG)?;
        self.header.assert_constructed()?;
        Ok(Sequence { content: self.data })
    }
}

pub impl SequenceCheckDerConstraints of CheckDerConstraints<Sequence> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        // TODO: iterate on ANY objects and check constraints? -> this will not be exhaustive
        // test, for ex INTEGER encoding will not be checked
        Ok(())
    }
}

pub impl SequenceTagged of Tagged<Sequence> {
    const TAG: Tag = TAG_SEQUENCE;
}
