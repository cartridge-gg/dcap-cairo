/// BER Object class of tag
#[derive(Drop, Debug, Copy, PartialEq)]
pub enum Class {
    /// `Universal` class of tags (`0b00`)
    Universal,
    /// `Application` class of tags (`0b01`)
    Application,
    /// `Context-Specific` class of tags (`0b10`)
    ContextSpecific,
    /// `Private` class of tags (`0b11`)
    Private,
}

#[generate_trait]
pub impl ClassImpl of ClassTrait {
    fn assert_eq(self: @Class, class: Class) -> Result<(), crate::error::Error> {
        if self == @class {
            Ok(())
        } else {
            Err(
                crate::error::Error::UnexpectedClass(
                    crate::error::UnexpectedClass { expected: Some(class), actual: *self },
                ),
            )
        }
    }
}

impl U8TryIntoClass of TryInto<u8, Class> {
    const fn try_into(self: u8) -> Option<Class> {
        match self {
            0b00 => Some(Class::Universal),
            0b01 => Some(Class::Application),
            0b10 => Some(Class::ContextSpecific),
            0b11 => Some(Class::Private),
            _ => None,
        }
    }
}

impl ClassIntoU8 of Into<Class, u8> {
    const fn into(self: Class) -> u8 {
        match self {
            Class::Universal => 0b00,
            Class::Application => 0b01,
            Class::ContextSpecific => 0b10,
            Class::Private => 0b11,
        }
    }
}
