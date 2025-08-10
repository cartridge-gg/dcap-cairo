use time::{DateTrait, OffsetDateTime, OffsetDateTimeTrait};
use crate::*;

#[derive(Drop, Debug, Clone)]
pub struct UtcTime {
    pub time: ASN1DateTime,
}

#[generate_trait]
pub impl UtcTimeImpl of UtcTimeTrait {
    fn new(datetime: ASN1DateTime) -> UtcTime {
        UtcTime { time: datetime }
    }

    fn from_bytes(bytes: @Span<u8>) -> Result<UtcTime, Error> {
        // X.680 section 43 defines a UniversalTime as a VisibleString restricted to:
        //
        // a) the six digits YYMMDD where YY is the two low-order digits of the Christian year, MM
        // is the month (counting January as 01), and DD is the day of the month (01 to 31); and
        // b) either:
        //   1) the four digits hhmm where hh is hour (00 to 23) and mm is minutes (00 to 59); or
        //   2) the six digits hhmmss where hh and mm are as in 1) above, and ss is seconds (00 to
        //   59); and
        // c) either:
        //   1) the character Z ; or
        //   2) one of the characters + or - , followed by hhmm, where hh is hour and mm is minutes.
        //
        // XXX // RFC 5280 requires mandatory seconds and Z-normalized time zone

        // CAIRO: Manual length and bounds checking instead of pattern matching
        if bytes.len() < 10 {
            return Result::Err(
                UtcTimeTagged::TAG.invalid_value("malformed time string (not yymmddhhmm)"),
            );
        }
        let year = decode_decimal(UtcTimeTagged::TAG, *bytes.at(0), *bytes.at(1))?;
        let month = decode_decimal(UtcTimeTagged::TAG, *bytes.at(2), *bytes.at(3))?;
        let day = decode_decimal(UtcTimeTagged::TAG, *bytes.at(4), *bytes.at(5))?;
        let hour = decode_decimal(UtcTimeTagged::TAG, *bytes.at(6), *bytes.at(7))?;
        let minute = decode_decimal(UtcTimeTagged::TAG, *bytes.at(8), *bytes.at(9))?;
        let rem_start = 10;
        if rem_start >= bytes.len() {
            return Result::Err(UtcTimeTagged::TAG.invalid_value("malformed time string"));
        }

        // check for seconds
        let (second, rem_start) = if rem_start + 1 < bytes.len() {
            let second = decode_decimal(
                UtcTimeTagged::TAG, *bytes.at(rem_start), *bytes.at(rem_start + 1),
            )?;
            (second, rem_start + 2)
        } else {
            (0, rem_start)
        };
        if month > 12 || day > 31 || hour > 23 || minute > 59 || second > 59 {
            return Result::Err(
                UtcTimeTagged::TAG.invalid_value("time components with invalid values"),
            );
        }
        if rem_start >= bytes.len() {
            return Result::Err(UtcTimeTagged::TAG.invalid_value("malformed time string"));
        }
        let tz = if rem_start + 1 == bytes.len() && *bytes.at(rem_start) == 0x5A { // 'Z'
            ASN1TimeZone::Z
        } else if rem_start + 5 == bytes.len() && *bytes.at(rem_start) == 0x2B { // '+'
            let hh = decode_decimal(
                UtcTimeTagged::TAG, *bytes.at(rem_start + 1), *bytes.at(rem_start + 2),
            )?;
            let mm = decode_decimal(
                UtcTimeTagged::TAG, *bytes.at(rem_start + 3), *bytes.at(rem_start + 4),
            )?;
            ASN1TimeZone::Offset((hh.try_into().unwrap(), mm.try_into().unwrap()))
        } else if rem_start + 5 == bytes.len() && *bytes.at(rem_start) == 0x2D { // '-'
            let hh = decode_decimal(
                UtcTimeTagged::TAG, *bytes.at(rem_start + 1), *bytes.at(rem_start + 2),
            )?;
            let mm = decode_decimal(
                UtcTimeTagged::TAG, *bytes.at(rem_start + 3), *bytes.at(rem_start + 4),
            )?;
            let hh_signed: i8 = -(hh.try_into().unwrap());
            ASN1TimeZone::Offset((hh_signed, mm.try_into().unwrap()))
        } else {
            return Result::Err(
                UtcTimeTagged::TAG.invalid_value("malformed time string: no time zone"),
            );
        };
        Ok(
            Self::new(
                ASN1DateTimeImpl::new(
                    year.into(), month, day, hour, minute, second, Option::None, tz,
                ),
            ),
        )
    }

    #[inline]
    fn utc_adjusted_datetime(self: @UtcTime) -> Result<OffsetDateTime, Error> {
        self
            .time
            .to_datetime()
            .and_then(
                |dt| {
                    let year = dt.year();
                    // We follow the Universal time definition in X.680 for interpreting
                    // the adjusted year
                    let year = if year >= 50 {
                        year + 1900
                    } else {
                        year + 2000
                    };
                    DateTrait::from_calendar_date(year, dt.month(), dt.day())
                        .map(|d| OffsetDateTimeTrait::replace_date(dt, d))
                        .map_err(|_e| UtcTimeTagged::TAG.invalid_value("Invalid adjusted date"))
                },
            )
    }
}

pub impl AnyTryIntoUtcTime of Into<Any, Result<UtcTime, Error>> {
    fn into(self: Any) -> Result<UtcTime, Error> {
        self.tag().assert_eq(UtcTimeTagged::TAG)?;
        // CAIRO: Check all bytes are visible characters
        let mut iter = self.data.clone();
        let mut is_any_invisible = false;
        while let Some(b) = iter.pop_front() {
            if !(0x20 <= *b && *b <= 0x7f) {
                is_any_invisible = true;
                break;
            }
        }

        if is_any_invisible {
            Result::Err(Error::StringInvalidCharset)
        } else {
            UtcTimeTrait::from_bytes(self.data)
        }
    }
}

pub impl UtcTimeCheckDerConstraints of CheckDerConstraints<UtcTime> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        Ok(())
    }
}

pub impl UtcTimeTagged of Tagged<UtcTime> {
    const TAG: Tag = TAG_UTCTIME;
}
