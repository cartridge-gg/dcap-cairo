use crate::*;

/// ASN.1 `OCTETSTRING` type
#[derive(Drop, Debug)]
pub struct OctetString {
    pub data: Span<u8>,
}

pub impl AnyTryIntoOctetString of Into<Any, Result<OctetString, Error>> {
    fn into(self: Any) -> Result<OctetString, Error> {
        self.tag().assert_eq(TaggedForOctetString::TAG)?;
        Ok(OctetString { data: *self.data })
    }
}

pub impl OctetStringCheckDerConstraints of CheckDerConstraints<OctetString> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        // X.690 section 10.2
        any.header.assert_primitive()?;
        Ok(())
    }
}

impl TaggedForOctetString of Tagged<OctetString> {
    const TAG: Tag = TAG_OCTETSTRING;
}

pub impl AnyTryIntoSpanU8 of Into<Any, Result<Span<u8>, Error>> {
    fn into(self: Any) -> Result<Span<u8>, Error> {
        self.tag().assert_eq(TaggedForSpanU8::TAG)?;
        let s = Into::<_, Result<OctetString, Error>>::into(self)?;
        Ok(s.data)
    }
}

pub impl SpanU8CheckDerConstraints of CheckDerConstraints<Span<u8>> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        // X.690 section 10.2
        any.header.assert_primitive()?;
        Ok(())
    }
}

impl TaggedForSpanU8 of Tagged<Span<u8>> {
    const TAG: Tag = TAG_OCTETSTRING;
}
