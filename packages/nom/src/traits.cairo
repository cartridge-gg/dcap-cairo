use crate::internal::{Needed, NeededImpl};

/// Abstracts common iteration operations on the input type
pub trait InputIter<SELF> {
    /// Get the byte offset from the element's position in the stream.
    fn slice_index(self: SELF, count: usize) -> Result<usize, Needed>;
}

/// Abstracts slicing operations
pub trait InputTake<SELF> {
    /// Returns a slice of `count` bytes. panics if count > length.
    fn take(self: SELF, count: usize) -> SELF;
    /// Split the stream at the `count` byte offset. panics if count > length.
    fn take_split(self: SELF, count: usize) -> (SELF, SELF);
}

impl SpanU8InputIter of InputIter<@Span<u8>> {
    fn slice_index(self: @Span<u8>, count: usize) -> Result<usize, Needed> {
        if self.len() >= count {
            Ok(count)
        } else {
            Err(NeededImpl::new(count - self.len()))
        }
    }
}

impl SpanU8InputTake of InputTake<@Span<u8>> {
    fn take(self: @Span<u8>, count: usize) -> @Span<u8> {
        @self.slice(0, count)
    }

    fn take_split(self: @Span<u8>, count: usize) -> (@Span<u8>, @Span<u8>) {
        (@self.slice(count, self.len() - count), @self.slice(0, count))
    }
}
