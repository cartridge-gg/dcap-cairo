use crate::error;

/// The clock time within a given date. Nanosecond precision.
///
/// All minutes are assumed to have exactly 60 seconds; no attempt is made to handle leap seconds
/// (either positive or negative).
///
/// When comparing two `Time`s, they are assumed to be in the same calendar date.
#[derive(Drop, Debug, Copy)]
pub struct Time {
    nanosecond: u32,
    second: u8,
    minute: u8,
    hour: u8,
}

#[generate_trait]
pub impl TimeImpl of TimeTrait {
    /// A `Time` that is exactly midnight. This is the smallest possible value for a `Time`.
    const MIDNIGHT: Time = Time { hour: 0, minute: 0, second: 0, nanosecond: 0 };

    /// Attempt to create a `Time` from the hour, minute, second, and millisecond.
    fn from_hms_milli(
        hour: u8, minute: u8, second: u8, millisecond: u16,
    ) -> Result<Time, error::ComponentRange> {
        if hour >= 24 {
            return Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Hour, minimum: 0, maximum: 23, value: hour.into(),
                },
            );
        }
        if minute >= 60 {
            return Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Minute,
                    minimum: 0,
                    maximum: 59,
                    value: minute.into(),
                },
            );
        }
        if second >= 60 {
            return Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Second,
                    minimum: 0,
                    maximum: 59,
                    value: second.into(),
                },
            );
        }
        if millisecond >= 1000 {
            return Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Millisecond,
                    minimum: 0,
                    maximum: 999,
                    value: millisecond.into(),
                },
            );
        }

        Ok(Time { hour, minute, second, nanosecond: millisecond.into() * 1_000_000 })
    }

    /// Get the clock hour.
    ///
    /// The returned value will always be in the range `0..24`.
    const fn hour(self: @Time) -> u8 {
        *self.hour
    }

    /// Get the minute within the hour.
    ///
    /// The returned value will always be in the range `0..60`.
    const fn minute(self: @Time) -> u8 {
        *self.minute
    }

    /// Get the second within the minute.
    ///
    /// The returned value will always be in the range `0..60`.
    const fn second(self: @Time) -> u8 {
        *self.second
    }
}
