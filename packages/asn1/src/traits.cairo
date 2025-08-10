use crate::error::*;
use crate::{Any, Class, Tag, parse_der_any};

/// Phantom type representing a BER parser
#[derive(Drop, Debug)]
pub enum BerParser {}

/// Phantom type representing a DER parser
#[derive(Drop, Debug)]
pub enum DerParser {}

pub trait Tagged<SELF> {
    const TAG: Tag;
}

/// Base trait for BER object parsers.
pub trait FromBer<SELF, E> {
    fn from_ber(bytes: @Span<u8>) -> ParseResult<SELF, E>;
}

/// Base trait for DER object parsers.
pub trait FromDer<SELF, E> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<SELF, E>;
}

pub impl FromDerViaAny<
    T,
    E,
    impl DerCon: CheckDerConstraints<T>,
    +Drop<T>,
    +Drop<E>,
    +Into<Any, Result<T, Error>>,
    +Into<Error, E>,
> of FromDer<T, E> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<T, E> {
        let (i, any) = parse_der_any(bytes).map_err(|err| nom::ErrTrait::convert(err))?;
        DerCon::check_constraints(@any).map_err(|e| nom::Err::Error(e.into()))?;
        let result = Into::<_, Result<T, Error>>::into(any).map_err(|e| nom::Err::Error(e.into()))?;
        Ok((i, result))
    }
}

/// Verification of DER constraints
pub trait CheckDerConstraints<T> {
    fn check_constraints(any: @Any) -> Result<(), Error>;
}
