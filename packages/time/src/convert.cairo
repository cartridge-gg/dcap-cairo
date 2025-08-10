// CAIRO: In Rust, these are implemented using a complex `Per` trait system (e.g.,
// Second::per(Day)).
// For Cairo, we use simple constants as the type system differences make the trait approach
// impractical.
//
// Time unit conversion constants
pub const SECONDS_PER_MINUTE: u8 = 60;
pub const SECONDS_PER_HOUR: u16 = 3_600;
pub const SECONDS_PER_DAY: u32 = 86_400;
