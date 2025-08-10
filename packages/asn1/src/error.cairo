use nom::IResult;
use nom::error::{ErrorKind, ParseError};
use crate::{Class, Tag};

/// Error types for DER constraints.
#[derive(Drop, Debug, Clone)]
pub enum DerConstraint {
    /// Indefinite length not allowed
    IndefiniteLength,
    /// Object must not be constructed
    Constructed,
    /// Object must be constructed
    NotConstructed,
    /// DateTime object is missing timezone
    MissingTimeZone,
    /// DateTime object is missing seconds
    MissingSeconds,
    /// Bitstring unused bits must be set to zero
    UnusedBitsNotZero,
    /// Boolean value must be 0x00 of 0xff
    InvalidBoolean,
    /// Integer must not be empty
    IntegerEmpty,
    /// Leading zeroes in Integer encoding
    IntegerLeadingZeroes,
    /// Leading 0xff in negative Integer encoding
    IntegerLeadingFF,
}

/// The error type for operations of the `FromBer`, `FromDer`, and associated traits.
#[derive(Drop, Debug, Clone)]
pub enum Error {
    /// BER object does not have the expected type
    BerTypeError,
    /// BER object does not have the expected value
    BerValueError,
    /// Invalid Length
    InvalidLength,
    /// Invalid Tag
    InvalidTag,
    /// Invalid Value when parsing object with tag {tag:?} {msg:}
    InvalidValue: InvalidValue,
    /// Unexpected Tag (expected: {expected:?}, actual: {actual:?})
    UnexpectedTag: UnexpectedTag,
    /// Unexpected Class (expected: {expected:?}, actual: {actual:?})
    UnexpectedClass: UnexpectedClass,
    /// Indefinite length not allowed
    IndefiniteLengthUnexpected,
    /// DER object was expected to be constructed (and found to be primitive)
    ConstructExpected,
    /// DER object was expected to be primitive (and found to be constructed)
    ConstructUnexpected,
    /// Integer too large to fit requested type
    IntegerTooLarge,
    /// BER integer is negative, while an unsigned integer was requested
    IntegerNegative,
    /// BER recursive parsing reached maximum depth
    BerMaxDepth,
    /// Invalid encoding or forbidden characters in string
    StringInvalidCharset,
    /// Invalid Date or Time
    InvalidDateTime,
    /// DER Failed constraint: {0:?}
    DerConstraintFailed: DerConstraint,
    /// incomplete data, missing: {0:?}
    Incomplete: nom::Needed,
    /// nom error: {0:?}
    NomError: ErrorKind,
}

#[derive(Drop, Debug, Clone)]
pub struct UnexpectedTag {
    pub expected: Option<Tag>,
    pub actual: Tag,
}

#[derive(Drop, Debug, Clone)]
pub struct InvalidValue {
    pub tag: Tag,
    pub msg: ByteArray,
}

#[derive(Drop, Debug, Clone)]
pub struct UnexpectedClass {
    pub expected: Option<Class>,
    pub actual: Class,
}

pub impl ErrorParseErrorImpl of ParseError<Error, @Span<u8>> {
    fn from_error_kind(input: @Span<u8>, kind: ErrorKind) -> Error {
        Error::NomError(kind)
    }

    fn append(input: @Span<u8>, kind: ErrorKind, other: Error) -> Error {
        Error::NomError(kind)
    }
}

impl ErrorToNomErr of Into<Error, nom::Err<Error>> {
    fn into(self: Error) -> nom::Err<Error> {
        nom::Err::Error(self)
    }
}

/// Holds the result of BER/DER serialization functions
pub type ParseResult<T, E> = IResult<@Span<u8>, T, E>;
