pub use asn1::Error;
use nom::IResult;
use crate::der::DerObject;

pub type BerError = Error;

/// Holds the result of parsing functions.
pub type BerResult<O> = IResult<@Span<u8>, O, BerError>;

/// Holds the result of parsing functions (DER)
pub type DerResult = BerResult<DerObject>;
