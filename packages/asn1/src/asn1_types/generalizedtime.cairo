use time::OffsetDateTime;
use crate::*;

#[derive(Drop, Debug, Clone)]
pub struct GeneralizedTime {
    pub time: ASN1DateTime,
}

#[generate_trait]
pub impl GeneralizedTimeImpl of GeneralizedTimeTrait {
    fn new(datetime: ASN1DateTime) -> GeneralizedTime {
        GeneralizedTime { time: datetime }
    }

    fn from_bytes(bytes: @Span<u8>) -> Result<GeneralizedTime, Error> {
        // X.680 section 42 defines a GeneralizedTime as a VisibleString restricted to:
        //
        // a) a string representing the calendar date, as specified in ISO 8601, with a four-digit
        // representation of the
        //    year, a two-digit representation of the month and a two-digit representation of the
        //    day, without use of separators, followed by a string representing the time of day, as
        //    specified in ISO 8601, without separators other than decimal comma or decimal period
        //    (as provided for in ISO 8601), and with no terminating Z (as provided for in ISO
        //    8601); or
        // b) the characters in a) above followed by an upper-case letter Z ; or
        // c) he characters in a) above followed by a string representing a local time differential,
        // as specified in
        //    ISO 8601, without separators.

        // CAIRO: Manual length and bounds checking instead of pattern matching
        if bytes.len() < 12 {
            return Result::Err(
                GeneralizedTimeTagged::TAG.invalid_value("malformed time string (not yymmddhhmm)"),
            );
        }
        let year_hi = decode_decimal(GeneralizedTimeTagged::TAG, *bytes.at(0), *bytes.at(1))?;
        let year_lo = decode_decimal(GeneralizedTimeTagged::TAG, *bytes.at(2), *bytes.at(3))?;
        let year = (year_hi.into() * 100_u32 + year_lo.into());
        let month = decode_decimal(GeneralizedTimeTagged::TAG, *bytes.at(4), *bytes.at(5))?;
        let day = decode_decimal(GeneralizedTimeTagged::TAG, *bytes.at(6), *bytes.at(7))?;
        let hour = decode_decimal(GeneralizedTimeTagged::TAG, *bytes.at(8), *bytes.at(9))?;
        let minute = decode_decimal(GeneralizedTimeTagged::TAG, *bytes.at(10), *bytes.at(11))?;
        let rem_start = 12;
        if rem_start >= bytes.len() {
            return Result::Err(GeneralizedTimeTagged::TAG.invalid_value("malformed time string"));
        }

        // check for seconds
        let (second, rem_start) = if rem_start + 1 < bytes.len() {
            let second = decode_decimal(
                GeneralizedTimeTagged::TAG, *bytes.at(rem_start), *bytes.at(rem_start + 1),
            )?;
            (second, rem_start + 2)
        } else {
            (0, rem_start)
        };
        if month > 12 || day > 31 || hour > 23 || minute > 59 || second > 59 {
            return Result::Err(
                GeneralizedTimeTagged::TAG.invalid_value("time components with invalid values"),
            );
        }
        if rem_start >= bytes.len() {
            // case a): no fractional seconds part, and no terminating Z
            return Ok(
                Self::new(
                    ASN1DateTimeImpl::new(
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        Option::None,
                        ASN1TimeZone::Undefined,
                    ),
                ),
            );
        }
        // check for fractional seconds
        let (millisecond, rem_start) = if rem_start < bytes.len()
            && (*bytes.at(rem_start) == 0x2E || *bytes.at(rem_start) == 0x2C) { // '.' or ','
            let mut fsecond: u16 = 0;
            let mut current_pos = rem_start + 1;
            let mut digits = 0;
            for idx in 0..=4_u32 {
                if current_pos >= bytes.len() {
                    if idx == 0 {
                        // dot or comma, but no following digit
                        return Result::Err(
                            GeneralizedTimeTagged::TAG
                                .invalid_value(
                                    "malformed time string (dot or comma but no digits)",
                                ),
                        );
                    }
                    digits = idx;
                    break;
                }
                if idx == 4 {
                    return Result::Err(
                        GeneralizedTimeTagged::TAG
                            .invalid_value("malformed time string (invalid milliseconds)"),
                    );
                }
                let b = *bytes.at(current_pos);
                if b >= 0x30 && b <= 0x39 { // '0'..'9'
                    // cannot overflow, max 4 digits will be read
                    fsecond = fsecond * 10 + (b - 0x30).into();
                } else if b == 0x5A || b == 0x2B || b == 0x2D { // 'Z' | '+' | '-'
                    digits = idx;
                    break;
                } else {
                    return Result::Err(
                        GeneralizedTimeTagged::TAG
                            .invalid_value("malformed time string (invalid milliseconds/timezone)"),
                    );
                }
                current_pos += 1;
            }
            // fix fractional seconds depending on the number of digits
            // for ex, date "xxxx.3" means 3000 milliseconds, not 3
            let fsecond = if digits == 1 {
                fsecond * 100
            } else if digits == 2 {
                fsecond * 10
            } else {
                fsecond
            };
            (Option::Some(fsecond), current_pos)
        } else {
            (Option::None, rem_start)
        };
        // check timezone
        if rem_start >= bytes.len() {
            // case a): fractional seconds part, and no terminating Z
            return Ok(
                Self::new(
                    ASN1DateTimeImpl::new(
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        millisecond,
                        ASN1TimeZone::Undefined,
                    ),
                ),
            );
        }
        let tz = if rem_start + 1 == bytes.len() && *bytes.at(rem_start) == 0x5A { // 'Z'
            ASN1TimeZone::Z
        } else if rem_start + 5 == bytes.len() && *bytes.at(rem_start) == 0x2B { // '+'
            let hh = decode_decimal(
                GeneralizedTimeTagged::TAG, *bytes.at(rem_start + 1), *bytes.at(rem_start + 2),
            )?;
            let mm = decode_decimal(
                GeneralizedTimeTagged::TAG, *bytes.at(rem_start + 3), *bytes.at(rem_start + 4),
            )?;
            ASN1TimeZone::Offset((hh.try_into().unwrap(), mm.try_into().unwrap()))
        } else if rem_start + 5 == bytes.len() && *bytes.at(rem_start) == 0x2D { // '-'
            let hh = decode_decimal(
                GeneralizedTimeTagged::TAG, *bytes.at(rem_start + 1), *bytes.at(rem_start + 2),
            )?;
            let mm = decode_decimal(
                GeneralizedTimeTagged::TAG, *bytes.at(rem_start + 3), *bytes.at(rem_start + 4),
            )?;
            let hh_signed: i8 = -(hh.try_into().unwrap());
            ASN1TimeZone::Offset((hh_signed, mm.try_into().unwrap()))
        } else {
            return Result::Err(
                GeneralizedTimeTagged::TAG.invalid_value("malformed time string: no time zone"),
            );
        };
        Ok(
            GeneralizedTime {
                time: ASN1DateTimeImpl::new(
                    year, month, day, hour, minute, second, millisecond, tz,
                ),
            },
        )
    }

    /// Return a ISO 8601 combined date and time with time zone.
    #[inline]
    fn utc_datetime(self: @GeneralizedTime) -> Result<OffsetDateTime, Error> {
        self.time.to_datetime()
    }
}

pub impl AnyTryIntoGeneralizedTime of Into<Any, Result<GeneralizedTime, Error>> {
    fn into(self: Any) -> Result<GeneralizedTime, Error> {
        self.tag().assert_eq(GeneralizedTimeTagged::TAG)?;
        let mut is_any_invisible = false;
        for b in self.data {
            if !(0x20 <= *b && *b <= 0x7f) {
                is_any_invisible = true;
                break;
            }
        }
        if is_any_invisible {
            return Result::Err(Error::StringInvalidCharset);
        }

        GeneralizedTimeTrait::from_bytes(self.data)
    }
}

pub impl GeneralizedTimeCheckDerConstraints of CheckDerConstraints<GeneralizedTime> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        // X.690 section 11.7.1: The encoding shall terminate with a "Z"
        if (*any.data).len() == 0 || *((*any.data).at((*any.data).len() - 1)) != 0x5A { // 'Z'
            return Result::Err(Error::DerConstraintFailed(DerConstraint::MissingTimeZone));
        }
        // X.690 section 11.7.2: The seconds element shall always be present.
        // XXX
        // X.690 section 11.7.4: The decimal point element, if present, shall be the point option
        // "."
        let mut has_comma = false;
        for b in any.data {
            if *b == 0x2C { // ','
                has_comma = true;
                break;
            }
        }
        if has_comma {
            return Result::Err(Error::DerConstraintFailed(DerConstraint::MissingSeconds));
        }
        Ok(())
    }
}

pub impl GeneralizedTimeTagged of Tagged<GeneralizedTime> {
    const TAG: Tag = TAG_GENERALIZEDTIME;
}
