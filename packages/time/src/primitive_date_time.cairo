use crate::{Date, OffsetDateTime, OffsetDateTimeTrait, Time, UtcOffset, UtcOffsetImpl};

/// Combined date and time.
#[derive(Drop, Debug, Copy)]
pub struct PrimitiveDateTime {
    date: Date,
    time: Time,
}

#[generate_trait]
pub impl PrimitiveDateTimeImpl of PrimitiveDateTimeTrait {
    /// Create a new `PrimitiveDateTime` from the provided [`Date`] and [`Time`].
    fn new(date: Date, time: Time) -> PrimitiveDateTime {
        PrimitiveDateTime { date, time }
    }

    /// Get the [`Date`] component of the `PrimitiveDateTime`.
    const fn date(self: @PrimitiveDateTime) -> Date {
        *self.date
    }

    /// Get the [`Time`] component of the `PrimitiveDateTime`.
    const fn time(self: @PrimitiveDateTime) -> Time {
        *self.time
    }

    /// Replace the date, preserving the time.
    fn replace_date(self: PrimitiveDateTime, date: Date) -> PrimitiveDateTime {
        PrimitiveDateTime { date, time: self.time }
    }

    /// Assuming that the existing `PrimitiveDateTime` represents a moment in the provided
    /// [`UtcOffset`], return an [`OffsetDateTime`].
    fn assume_offset(self: PrimitiveDateTime, offset: UtcOffset) -> OffsetDateTime {
        OffsetDateTimeTrait::new_in_offset(self.date, self.time, offset)
    }

    /// Assuming that the existing `PrimitiveDateTime` represents a moment in UTC, return an
    /// [`OffsetDateTime`].
    fn assume_utc(self: PrimitiveDateTime) -> OffsetDateTime {
        self.assume_offset(UtcOffsetImpl::UTC)
    }
}
