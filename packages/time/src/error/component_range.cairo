//! Component range error

// CAIRO: Using enum instead of &'static str to avoid expensive ByteArray allocations
//
/// Component name for ComponentRange errors.
#[derive(Drop, Debug, PartialEq, Copy)]
pub enum ComponentName {
    Day,
    Hour,
    Microsecond,
    Millisecond,
    Minute,
    Month,
    Nanosecond,
    Ordinal,
    Second,
    Week,
    Year,
}

// CAIRO: Removed conditional_message field as it's not essential and would be expensive with
// ByteArray
//
/// An error type indicating that a component provided to a method was out of range, causing a
/// failure.
#[derive(Drop, Debug, PartialEq)]
pub struct ComponentRange {
    // CAIRO: Using ComponentName enum instead of &'static str to avoid expensive ByteArray
    //
    /// Name of the component.
    pub(crate) name: ComponentName,
    /// Minimum allowed value, inclusive.
    pub(crate) minimum: i64,
    /// Maximum allowed value, inclusive.
    pub(crate) maximum: i64,
    /// Value that was provided.
    pub(crate) value: i64,
}

#[generate_trait]
pub impl ComponentRangeImpl of ComponentRangeTrait {
    /// Obtain the name of the component whose value was out of range.
    fn name(self: @ComponentRange) -> ComponentName {
        *self.name
    }
}
