//! Utility functions.

use crate::Month;

/// Determine if the provided year is a leap year in the proleptic Gregorian calendar.
pub const fn is_leap_year(year: i32) -> bool {
    let d: u32 = if year % 100 == 0 {
        15
    } else {
        3
    };
    TryInto::<_, u32>::try_into(year).unwrap() & d == 0
}

/// Get the number of calendar days in a given year.
///
/// The returned value will always be either 365 or 366.
pub const fn days_in_year(year: i32) -> u16 {
    if is_leap_year(year) {
        366
    } else {
        365
    }
}

/// Get the number of days in the month of a given year.
pub const fn days_in_month(month: Month, year: i32) -> u8 {
    // CAIRO: Rewrote with direct matching.
    match month {
        Month::February => { if is_leap_year(year) {
            29
        } else {
            28
        } },
        Month::January | Month::March | Month::May | Month::July | Month::August | Month::October |
        Month::December => 31,
        Month::April | Month::June | Month::September | Month::November => 30,
    }
}
