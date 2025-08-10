use crate::*;
use crate::ber::*;

/// The `Any` object is not strictly an ASN.1 type, but holds a generic description of any object
/// that could be encoded.
#[derive(Drop, Debug, Clone, PartialEq)]
pub struct Any {
    /// The object header.
    pub header: Header,
    /// The object contents.
    pub data: @Span<u8>,
}

#[generate_trait]
pub impl AnyImpl of AnyTrait {
    /// Create a new `Any` from BER/DER header and content
    #[inline]
    const fn new(header: Header, data: @Span<u8>) -> Any {
        Any { header, data }
    }

    fn class(self: @Any) -> @Class {
        self.header.class
    }

    fn tag(self: @Any) -> @Tag {
        self.header.tag
    }

    /// Get the bytes representation of the *content*.
    #[inline]
    fn as_bytes(self: @Any) -> @Span<u8> {
        *self.data
    }
}

impl AnyTryIntoBool of Into<Any, Result<bool, Error>> {
    fn into(self: Any) -> Result<bool, Error> {
        self.tag().assert_eq(BoolTagged::TAG)?;
        let b = Into::<Any, Result<Boolean, Error>>::into(self)?;
        Ok(b.bool())
    }
}

pub(crate) fn parse_ber_any(input: @Span<u8>) -> ParseResult<Any, Error> {
    let (i, header) = FromBer::<Header>::from_ber(input)?;
    let (i, data) = BerParserGetObjectContent::get_object_content(i, @header, MAX_RECURSION)?;
    Ok((i, Any { header, data }))
}

pub(crate) fn parse_der_any(input: @Span<u8>) -> ParseResult<Any, Error> {
    let (i, header) = FromDer::<Header>::from_der(input)?;
    // X.690 section 10.1: The definite form of length encoding shall be used
    header.length.assert_definite().map_err(|err| err.into())?;
    let (i, data) = DerParserGetObjectContent::get_object_content(i, @header, MAX_RECURSION)?;
    Ok((i, Any { header, data }))
}

pub impl AnyFromBer of FromBer<Any, Error> {
    fn from_ber(bytes: @Span<u8>) -> ParseResult<Any, Error> {
        parse_ber_any(bytes)
    }
}

pub impl AnyFromDer of FromDer<Any, Error> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<Any, Error> {
        parse_der_any(bytes)
    }
}
