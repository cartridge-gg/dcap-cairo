use asn1::{Any, AnyTrait, Class, ClassTrait, Error, FromDer, UnexpectedTag};
use nom::IResult;

/// Represents a GeneralName as defined in RFC5280. There
/// is no support X.400 addresses and EDIPartyName.
///
/// String formats are not validated.
#[derive(Drop, Debug)]
pub enum GeneralName {
    /// An uniform resource identifier. The format is not checked.
    URI: @Span<u8>,
}

pub impl AnyTryIntoGeneralName of Into<Any, Result<GeneralName, Error>> {
    fn into(self: Any) -> Result<GeneralName, Error> {
        self.class().assert_eq(Class::ContextSpecific)?;

        // CAIRO: Skipped UTF-8 validation.
        let name = if *self.tag().tag == 6 {
            GeneralName::URI(self.data)
        } else if *self.tag().tag <= 8 {
            panic!("GeneralName tag not implemented")
        } else {
            return Err(Error::UnexpectedTag(UnexpectedTag { expected: None, actual: *self.tag() }));
        };
        Ok(name)
    }
}

pub(crate) fn parse_generalname(i: @Span<u8>) -> IResult<@Span<u8>, GeneralName, Error> {
    let (rest, any) = FromDer::<Any>::from_der(i)?;
    let gn = Into::<Any, Result<GeneralName, Error>>::into(any).map_err(|e| e.into())?;
    Ok((rest, gn))
}
