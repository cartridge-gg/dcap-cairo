/// This trait must be implemented by the error type of a nom parser.
pub trait ParseError<SELF, I> {
    /// Creates an error from the input position and an [ErrorKind]
    fn from_error_kind(input: I, kind: ErrorKind) -> SELF;

    /// Combines an existing error with a new one created from the input
    /// position and an [ErrorKind]. This is useful when backtracking
    /// through a parse tree, accumulating error context on the way
    fn append(input: I, kind: ErrorKind, other: SELF) -> SELF;
}

/// default error type, only contains the error' location and code.
#[derive(Drop, Debug)]
pub struct Error<I> {
    /// position of the error in the input data.
    pub input: I,
    /// nom error code
    pub code: ErrorKind,
}

#[derive(Drop, Debug, Clone)]
pub enum ErrorKind {
    Alt,
    Many0,
    Many1,
    Eof,
    Complete,
}
