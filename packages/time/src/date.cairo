use crate::util::{days_in_year, is_leap_year};
use crate::{Month, MonthTrait, PrimitiveDateTime, PrimitiveDateTimeTrait, Time, error};

// CAIRO: Using smaller year range since we don't have large-dates feature
const MIN_YEAR: i32 = -9999;
const MAX_YEAR: i32 = 9999;

/// Date in the proleptic Gregorian calendar.
///
/// By default, years between ±9999 inclusive are representable. This can be expanded to ±999,999
/// inclusive by enabling the `large-dates` crate feature. Doing so has performance implications
/// and introduces some ambiguities when parsing.
#[derive(Drop, Debug, Copy)]
pub struct Date {
    value: NonZero<i32>,
}

#[generate_trait]
pub impl DateImpl of DateTrait {
    /// Attempt to create a `Date` from the year, month, and day.
    fn from_calendar_date(year: i32, month: Month, day: u8) -> Result<Date, error::ComponentRange> {
        // CAIRO: Rewrote `DAYS_CUMULATIVE_COMMON_LEAP` as `days_before_month()`.

        if year < MIN_YEAR || year > MAX_YEAR {
            return Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Year,
                    minimum: MIN_YEAR.into(),
                    maximum: MAX_YEAR.into(),
                    value: year.into(),
                },
            );
        }

        if !((day >= 1 && day <= 28) || (day >= 29 && day <= 31 && day <= month.length(year))) {
            return Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Day,
                    minimum: 1,
                    maximum: month.length(year).into(),
                    value: day.into(),
                },
            );
        }

        // Safety: `ordinal` is not zero.
        Ok(
            Self::__from_ordinal_date_unchecked(
                year, days_before_month(month, is_leap_year(year)) + day.into(),
            ),
        )
    }

    /// Get the year of the date.
    fn year(self: @Date) -> i32 {
        (*self.value).into() / 0b100_0000_0000
    }

    /// Get the month.
    fn month(self: @Date) -> Month {
        let ordinal: u32 = self.ordinal().into();
        let jan_feb_len: u32 = 59 + if self.is_in_leap_year() {
            1
        } else {
            0
        };

        let (month_adj, ordinal_adj) = if ordinal <= jan_feb_len {
            (0, 0)
        } else {
            (2, jan_feb_len)
        };

        let ordinal = ordinal - ordinal_adj;
        let month = ((ordinal * 268 + 8031) / 0b10_0000_0000_0000) + month_adj;

        // Safety: `month` is guaranteed to be between 1 and 12 inclusive.
        MonthTrait::from_number(month.try_into().unwrap()).unwrap()
    }

    /// Get the day of the month.
    ///
    /// The returned value will always be in the range `1..=31`.
    fn day(self: @Date) -> u8 {
        let ordinal: u32 = self.ordinal().into();
        let jan_feb_len: u32 = 59 + if self.is_in_leap_year() {
            1
        } else {
            0
        };

        let ordinal_adj = if ordinal <= jan_feb_len {
            0
        } else {
            jan_feb_len
        };

        let ordinal = ordinal - ordinal_adj;
        let month = (ordinal * 268 + 8031)
            / 0b10_0000_0000_0000; // CAIRO: Using division instead of bit shift >> 13
        let days_in_preceding_months = (month * 3917 - 3866)
            / 0b10000000; // CAIRO: Using division instead of bit shift >> 7
        (ordinal - days_in_preceding_months).try_into().unwrap()
    }

    /// Create a [`PrimitiveDateTime`] using the existing date. The [`Time`] component will be set
    /// to the provided value.
    fn with_time(self: Date, time: Time) -> PrimitiveDateTime {
        PrimitiveDateTimeTrait::new(self, time)
    }

    /// Construct a `Date` from the year and ordinal values, the validity of which must be
    /// guaranteed by the caller.
    ///
    /// # Safety
    ///
    /// `ordinal` must be non-zero and at most the number of days in `year`. `year` should be in the
    /// range `MIN_YEAR..=MAX_YEAR`, but this is not a safety invariant.
    fn __from_ordinal_date_unchecked(year: i32, ordinal: u16) -> Date {
        // Safety: The caller must guarantee that `ordinal` is not zero.
        Self::from_parts(year, is_leap_year(year), ordinal)
    }

    /// Construct a `Date` from its internal representation, the validity of which must be
    /// guaranteed by the caller.
    ///
    /// # Safety
    ///
    /// - `ordinal` must be non-zero and at most the number of days in `year`
    /// - `is_leap_year` must be `true` if and only if `year` is a leap year
    fn from_parts(year: i32, is_leap_year: bool, ordinal: u16) -> Date {
        assert!(year >= MIN_YEAR);
        assert!(year <= MAX_YEAR);
        assert!(ordinal != 0);
        assert!(ordinal <= days_in_year(year));
        assert!(crate::util::is_leap_year(year) == is_leap_year);

        // Safety: `ordinal` is not zero.
        Date {
            value: TryInto::<
                i32, NonZero<i32>,
            >::try_into(
                year * 0b100_0000_0000
                    + if is_leap_year {
                        0b10_0000_0000
                    } else {
                        0
                    }
                    + ordinal.into(),
            )
                .unwrap(),
        }
    }

    /// Get the day of the year.
    ///
    /// The returned value will always be in the range `1..=366` (`1..=365` for common years).
    fn ordinal(self: @Date) -> u16 {
        let value_i32: i32 = (*self.value).into();
        let value: u32 = value_i32.try_into().unwrap();
        (value & 0x1FF).try_into().unwrap()
    }

    /// Whether `is_leap_year(self.year())` is `true`.
    ///
    /// This method is optimized to take advantage of the fact that the value is pre-computed upon
    /// construction and stored in the bitpacked struct.
    fn is_in_leap_year(self: @Date) -> bool {
        let value_i32: i32 = (*self.value).into();
        let value: u32 = value_i32.try_into().unwrap();
        ((value / 0b10_0000_0000) % 2) == 1 // CAIRO: Using division instead of bit shift
    }

    /// Get the year and ordinal day of the year.
    fn to_ordinal_date(self: @Date) -> (i32, u16) {
        (self.year(), self.ordinal())
    }

    /// Get the Julian day for the date.
    fn to_julian_day(self: @Date) -> i32 {
        let (year, ordinal) = self.to_ordinal_date();

        // The algorithm requires a non-negative year. Add the lowest value to make it so. This is
        // adjusted for at the end with the final subtraction.
        let adj_year = year + 999_999;
        let century = adj_year / 100;

        let days_before_year = (1461_i64 * adj_year.into() / 4).try_into().unwrap()
            - century
            + century / 4;
        days_before_year + ordinal.into() - 363_521_075
    }
}

/// Get cumulative days before the start of a given month.
const fn days_before_month(month: Month, is_leap: bool) -> u16 {
    match month {
        Month::January => 0,
        Month::February => 31,
        Month::March => if is_leap {
            60
        } else {
            59
        },
        Month::April => if is_leap {
            91
        } else {
            90
        },
        Month::May => if is_leap {
            121
        } else {
            120
        },
        Month::June => if is_leap {
            152
        } else {
            151
        },
        Month::July => if is_leap {
            182
        } else {
            181
        },
        Month::August => if is_leap {
            213
        } else {
            212
        },
        Month::September => if is_leap {
            244
        } else {
            243
        },
        Month::October => if is_leap {
            274
        } else {
            273
        },
        Month::November => if is_leap {
            305
        } else {
            304
        },
        Month::December => if is_leap {
            335
        } else {
            334
        },
    }
}
