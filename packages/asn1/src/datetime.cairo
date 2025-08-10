use time::{
    DateTrait, Month, OffsetDateTime, PrimitiveDateTimeTrait, TimeTrait, U8TryIntoMonth,
    UtcOffsetImpl, UtcOffsetTrait, error,
};
use crate::{Error, Tag, TagTrait};

#[derive(Drop, Debug, Clone)]
pub enum ASN1TimeZone {
    /// No timezone provided
    Undefined,
    /// Coordinated universal time
    Z,
    /// Local zone, with offset to coordinated universal time
    ///
    /// `(offset_hour, offset_minute)`
    Offset: (i8, i8),
}

#[derive(Drop, Debug, Clone)]
pub struct ASN1DateTime {
    pub year: u32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub millisecond: Option<u16>,
    pub tz: ASN1TimeZone,
}

#[generate_trait]
pub impl ASN1DateTimeImpl of ASN1DateTimeTrait {
    fn new(
        year: u32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        millisecond: Option<u16>,
        tz: ASN1TimeZone,
    ) -> ASN1DateTime {
        ASN1DateTime { year, month, day, hour, minute, second, millisecond, tz }
    }

    fn to_time_datetime(self: @ASN1DateTime) -> Result<OffsetDateTime, error::ComponentRange> {
        let month = Into::<_, Result<Month, _>>::into(*self.month)?;
        let date = DateTrait::from_calendar_date(
            (*self.year).try_into().unwrap(), month, *self.day,
        )?;
        let time = TimeTrait::from_hms_milli(
            *self.hour, *self.minute, *self.second, self.millisecond.unwrap_or(0),
        )?;
        let primitive_date = PrimitiveDateTimeTrait::new(date, time);
        let offset = match self.tz {
            ASN1TimeZone::Offset((h, m)) => UtcOffsetTrait::from_hms(*h, *m, 0)?,
            ASN1TimeZone::Undefined | ASN1TimeZone::Z => UtcOffsetImpl::UTC,
        };
        Ok(primitive_date.assume_offset(offset))
    }

    fn to_datetime(self: @ASN1DateTime) -> Result<OffsetDateTime, Error> {
        self.to_time_datetime().map_err(|_err| Error::InvalidDateTime)
    }
}

/// Decode 2-digit decimal value
pub(crate) fn decode_decimal(tag: Tag, hi: u8, lo: u8) -> Result<u8, Error> {
    // CAIRO: Manual ASCII digit check instead of is_ascii_digit()
    if (hi >= 0x30 && hi <= 0x39) && (lo >= 0x30 && lo <= 0x39) {
        Ok((hi - 0x30) * 10 + (lo - 0x30))
    } else {
        Result::Err(tag.invalid_value("expected digit"))
    }
}
