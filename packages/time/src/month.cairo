//! The `Month` enum and its associated `impl`s.

use crate::{error, util};

/// Months of the year.
#[derive(Drop, Debug, Copy, PartialEq)]
pub enum Month {
    January,
    February,
    March,
    April,
    May,
    June,
    July,
    August,
    September,
    October,
    November,
    December,
}

#[generate_trait]
pub impl MonthImpl of MonthTrait {
    /// Create a `Month` from its numerical value.
    fn from_number(n: u8) -> Result<Month, error::ComponentRange> {
        if n == 1 {
            Ok(Month::January)
        } else if n == 2 {
            Ok(Month::February)
        } else if n == 3 {
            Ok(Month::March)
        } else if n == 4 {
            Ok(Month::April)
        } else if n == 5 {
            Ok(Month::May)
        } else if n == 6 {
            Ok(Month::June)
        } else if n == 7 {
            Ok(Month::July)
        } else if n == 8 {
            Ok(Month::August)
        } else if n == 9 {
            Ok(Month::September)
        } else if n == 10 {
            Ok(Month::October)
        } else if n == 11 {
            Ok(Month::November)
        } else if n == 12 {
            Ok(Month::December)
        } else {
            Result::Err(
                error::ComponentRange {
                    name: error::ComponentName::Month, minimum: 1, maximum: 12, value: n.into(),
                },
            )
        }
    }

    /// Get the number of days in the month of a given year.
    fn length(self: Month, year: i32) -> u8 {
        util::days_in_month(self, year)
    }

    /// Get the previous month.
    fn previous(self: Month) -> Month {
        match self {
            Month::January => Month::December,
            Month::February => Month::January,
            Month::March => Month::February,
            Month::April => Month::March,
            Month::May => Month::April,
            Month::June => Month::May,
            Month::July => Month::June,
            Month::August => Month::July,
            Month::September => Month::August,
            Month::October => Month::September,
            Month::November => Month::October,
            Month::December => Month::November,
        }
    }

    /// Get the next month.
    fn next(self: Month) -> Month {
        match self {
            Month::January => Month::February,
            Month::February => Month::March,
            Month::March => Month::April,
            Month::April => Month::May,
            Month::May => Month::June,
            Month::June => Month::July,
            Month::July => Month::August,
            Month::August => Month::September,
            Month::September => Month::October,
            Month::October => Month::November,
            Month::November => Month::December,
            Month::December => Month::January,
        }
    }
}

impl MonthIntoU8 of Into<Month, u8> {
    fn into(self: Month) -> u8 {
        match self {
            Month::January => 1,
            Month::February => 2,
            Month::March => 3,
            Month::April => 4,
            Month::May => 5,
            Month::June => 6,
            Month::July => 7,
            Month::August => 8,
            Month::September => 9,
            Month::October => 10,
            Month::November => 11,
            Month::December => 12,
        }
    }
}

pub impl U8TryIntoMonth of Into<u8, Result<Month, error::ComponentRange>> {
    fn into(self: u8) -> Result<Month, error::ComponentRange> {
        MonthTrait::from_number(self)
    }
}
