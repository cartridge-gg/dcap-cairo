use crate::{
    Date, DateTrait, Month, PrimitiveDateTime, PrimitiveDateTimeTrait, Time, TimeTrait, UtcOffset,
    UtcOffsetImpl, UtcOffsetTrait,
};

// CAIRO: Using hardcoded value instead of computed constant
// The Julian day of the Unix epoch.
const UNIX_EPOCH_JULIAN_DAY: i32 = 2_440_588;

/// A [`PrimitiveDateTime`] with a [`UtcOffset`].
///
/// All comparisons are performed using the UTC time.
#[derive(Drop, Debug, Copy)]
pub struct OffsetDateTime {
    local_date_time: PrimitiveDateTime,
    offset: UtcOffset,
}

#[generate_trait]
pub impl OffsetDateTimeImpl of OffsetDateTimeTrait {
    // CAIRO: Cannot define UNIX_EPOCH as a const because const functions are limited in Cairo
    // Will need to implement as a function instead
    /// Midnight, 1 January, 1970 (UTC).
    fn unix_epoch() -> OffsetDateTime {
        let date = DateTrait::__from_ordinal_date_unchecked(1970, 1);
        Self::new_in_offset(date, TimeTrait::MIDNIGHT, UtcOffsetImpl::UTC)
    }

    /// Create a new `OffsetDateTime` with the given [`Date`], [`Time`], and [`UtcOffset`].
    fn new_in_offset(date: Date, time: Time, offset: UtcOffset) -> OffsetDateTime {
        OffsetDateTime { local_date_time: date.with_time(time), offset }
    }

    /// Create a new `OffsetDateTime` with the given [`Date`] and [`Time`] in the UTC timezone.
    fn new_utc(date: Date, time: Time) -> OffsetDateTime {
        PrimitiveDateTimeTrait::new(date, time).assume_utc()
    }

    /// Get the [`UtcOffset`].
    const fn offset(self: @OffsetDateTime) -> UtcOffset {
        *self.offset
    }

    /// Get the [`Time`] in the stored offset.
    fn time(self: @OffsetDateTime) -> Time {
        self.date_time().time()
    }

    /// Get the year of the date in the stored offset.
    fn year(self: @OffsetDateTime) -> i32 {
        self.date().year()
    }

    /// Get the month of the date in the stored offset.
    fn month(self: @OffsetDateTime) -> Month {
        self.date().month()
    }

    /// Get the day of the date in the stored offset.
    ///
    /// The returned value will always be in the range `1..=31`.
    fn day(self: @OffsetDateTime) -> u8 {
        self.date().day()
    }

    /// Get the [`PrimitiveDateTime`] in the stored offset.
    const fn date_time(self: @OffsetDateTime) -> PrimitiveDateTime {
        *self.local_date_time
    }

    /// Get the [`Date`] in the stored offset.
    fn date(self: @OffsetDateTime) -> Date {
        self.date_time().date()
    }

    /// Replace the date, which is assumed to be in the same calendar as the original.
    fn replace_date(self: OffsetDateTime, date: Date) -> OffsetDateTime {
        Self::new_in_offset(date, self.time(), self.offset())
    }

    /// Get the clock hour in the stored offset.
    ///
    /// The returned value will always be in the range `0..24`.
    fn hour(self: @OffsetDateTime) -> u8 {
        self.time().hour()
    }

    /// Get the minute within the hour in the stored offset.
    ///
    /// The returned value will always be in the range `0..60`.
    fn minute(self: @OffsetDateTime) -> u8 {
        self.time().minute()
    }

    /// Get the second within the minute in the stored offset.
    ///
    /// The returned value will always be in the range `0..60`.
    fn second(self: @OffsetDateTime) -> u8 {
        self.time().second()
    }

    /// Get the Julian day for the date. The time is not taken into account for this calculation.
    ///
    /// The algorithm to perform this conversion is derived from one provided by Peter Baum; it is
    /// freely available [here](https://www.researchgate.net/publication/316558298_Date_Algorithms).
    fn to_julian_day(self: @OffsetDateTime) -> i32 {
        self.date().to_julian_day()
    }

    /// Get the [Unix timestamp](https://en.wikipedia.org/wiki/Unix_time).
    fn unix_timestamp(self: @OffsetDateTime) -> i64 {
        // CAIRO: Using constants instead of Rust's Second::per(Day), Second::per(Hour), etc.
        let days: i64 = (self.to_julian_day().into() - UNIX_EPOCH_JULIAN_DAY.into())
            * crate::convert::SECONDS_PER_DAY.into();
        let hours: i64 = self.hour().into() * crate::convert::SECONDS_PER_HOUR.into();
        let minutes: i64 = self.minute().into() * crate::convert::SECONDS_PER_MINUTE.into();
        let seconds: i64 = self.second().into();
        let offset_seconds: i64 = self.offset().whole_seconds().into();
        days + hours + minutes + seconds - offset_seconds
    }
}
