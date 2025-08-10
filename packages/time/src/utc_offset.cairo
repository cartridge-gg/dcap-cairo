/// An offset from UTC.
///
/// This struct can store values up to ±25:59:59. If you need support outside this range, please
/// file an issue with your use case.
// All three components _must_ have the same sign.
#[derive(Drop, Debug, Copy)]
pub struct UtcOffset {
    hours: i8,
    minutes: i8,
    seconds: i8,
}

#[generate_trait]
pub impl UtcOffsetImpl of UtcOffsetTrait {
    /// A `UtcOffset` that is UTC.
    const UTC: UtcOffset = UtcOffset { hours: 0, minutes: 0, seconds: 0 };

    /// Create a `UtcOffset` representing an offset of the hours, minutes, and seconds provided, the
    /// validity of which must be guaranteed by the caller. All three parameters must have the same
    /// sign.
    fn from_hms(
        hours: i8, minutes: i8, seconds: i8,
    ) -> Result<UtcOffset, crate::error::ComponentRange> {
        panic!("TODO: UtcOffsetImpl::from_hms")
    }

    /// Obtain the total offset in seconds.
    // This may be useful for anyone manually implementing arithmetic, as it
    // would let them construct a `Duration` directly.
    fn whole_seconds(self: @UtcOffset) -> i32 {
        // CAIRO: Using constants instead of Rust's Second::per(Hour) and Second::per(Minute)
        (*self.hours).into() * crate::convert::SECONDS_PER_HOUR.into()
            + (*self.minutes).into() * crate::convert::SECONDS_PER_MINUTE.into()
            + (*self.seconds).into()
    }
}
