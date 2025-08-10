use asn1::{
    Error, FromDer, GeneralizedTime, GeneralizedTimeTrait, HeaderFromDer, HeaderTrait, LengthTrait,
    ParseResult, TAG_UTCTIME, UnexpectedTag, UtcTime, UtcTimeTrait,
};
use der_parser::ber::MAX_OBJECT_SIZE;
use nom::Err;
use time::{OffsetDateTime, OffsetDateTimeTrait};
use crate::error::{X509Error, X509Result};

/// An ASN.1 timestamp.
#[derive(Drop, Debug, Clone)]
pub struct ASN1Time {
    time: OffsetDateTime,
    generalized: bool,
}

#[generate_trait]
pub impl ASN1TimeImpl of ASN1TimeTrait {
    #[inline]
    const fn new_generalized(dt: OffsetDateTime) -> ASN1Time {
        ASN1Time { time: dt, generalized: true }
    }

    #[inline]
    const fn new_utc(dt: OffsetDateTime) -> ASN1Time {
        ASN1Time { time: dt, generalized: false }
    }

    /// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC (aka "UNIX
    /// timestamp").
    #[inline]
    fn timestamp(self: @ASN1Time) -> i64 {
        self.time.unix_timestamp()
    }
}

pub impl ASN1TimeFromDer of FromDer<ASN1Time, X509Error> {
    fn from_der(bytes: @Span<u8>) -> X509Result<ASN1Time> {
        let (rem, time) = parse_choice_of_time(bytes)
            .map_err(|_unused| Err::Error(X509Error::InvalidDate))?;
        Ok((rem, time))
    }
}

pub(crate) fn parse_choice_of_time(i: @Span<u8>) -> ParseResult<ASN1Time, Error> {
    if let Ok((rem, t)) = FromDer::<UtcTime, X509Error>::from_der(i) {
        let dt = t.utc_adjusted_datetime().map_err(|err| Err::Error(err.into()))?;
        return Ok((rem, ASN1TimeTrait::new_utc(dt)));
    }
    if let Ok((rem, t)) = FromDer::<GeneralizedTime, X509Error>::from_der(i) {
        let dt = t.utc_datetime().map_err(|err| Err::Error(err.into()))?;
        return Ok((rem, ASN1TimeTrait::new_generalized(dt)));
    }
    parse_malformed_date(i)
}

// allow relaxed parsing of UTCTime (ex: 370116130016+0000)
fn parse_malformed_date(i: @Span<u8>) -> ParseResult<ASN1Time, Error> {
    let (_rem, hdr) = HeaderFromDer::from_der(i)?;
    let len = hdr.length().definite().map_err(|err| err.into())?;
    if len > MAX_OBJECT_SIZE {
        return Result::Err(Err::Error(Error::InvalidLength));
    }

    if *hdr.tag() == TAG_UTCTIME {
        Result::Err(Err::Error(Error::BerValueError))
    } else {
        Result::Err(
            Err::Error(
                Error::UnexpectedTag(UnexpectedTag { expected: Option::None, actual: *hdr.tag() }),
            ),
        )
    }
}
