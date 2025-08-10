use crate::*;
use crate::ber::bytes_to_u64;

/// ASN.1 `ENUMERATED` type
///
/// # Limitations
///
/// Supported values are limited to 0 .. 2^32
#[derive(Drop, Debug)]
pub struct Enumerated {
    pub data: u32,
}

pub impl AnyTryIntoEnumerated of Into<Any, Result<Enumerated, Error>> {
    fn into(self: Any) -> Result<Enumerated, Error> {
        self.tag().assert_eq(TaggedForEnumerated::TAG)?;
        self.header.assert_primitive()?;
        let res_u64 = bytes_to_u64(self.data)?;
        match TryInto::<u64, u32>::try_into(res_u64) {
            Some(value) => Ok(Enumerated { data: value }),
            None => Result::Err(Error::IntegerTooLarge),
        }
    }
}

pub impl EnumeratedCheckDerConstraints of CheckDerConstraints<Enumerated> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        any.header.length.assert_definite()?;
        Ok(())
    }
}

impl TaggedForEnumerated of Tagged<Enumerated> {
    const TAG: Tag = TAG_ENUMERATED;
}
