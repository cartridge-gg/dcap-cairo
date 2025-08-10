use der_parser::error::BerError;
use nom::IResult;
use nom::error::{ErrorKind, ParseError};

/// Holds the result of parsing functions (X.509).
pub type X509Result<T> = IResult<@Span<u8>, T, X509Error>;

/// An error that can occur while parsing or validating a certificate.
#[derive(Drop, Debug, Clone)]
pub enum X509Error {
    InvalidVersion,
    InvalidSerial,
    InvalidAlgorithmIdentifier,
    InvalidX509Name,
    InvalidDate,
    InvalidSPKI,
    InvalidSubjectUID,
    InvalidIssuerUID,
    InvalidExtensions,
    DuplicateExtensions,
    InvalidSignatureValue,
    Der: BerError,
    NomError: ErrorKind,
}

pub impl BerErrorIntoX509ErrorImpl of Into<BerError, X509Error> {
    fn into(self: BerError) -> X509Error {
        X509Error::Der(self)
    }
}

pub impl X509ErrorIntoErr of Into<X509Error, nom::Err<X509Error>> {
    fn into(self: X509Error) -> nom::Err<X509Error> {
        nom::Err::Error(self)
    }
}

pub impl X509ErrorParseErrorImpl of ParseError<X509Error, @Span<u8>> {
    fn from_error_kind(input: @Span<u8>, kind: ErrorKind) -> X509Error {
        X509Error::NomError(kind)
    }

    fn append(input: @Span<u8>, kind: ErrorKind, other: X509Error) -> X509Error {
        X509Error::NomError(kind)
    }
}
