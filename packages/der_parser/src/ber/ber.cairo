use asn1::Any;
use int_traits::U32FromBeBytes;
use crate::ber::integer::*;
use crate::error::BerError;
use super::Header;

/// Representation of a BER-encoded (X.690) object.
///
/// A BER object is composed of a header describing the object class, type and length,
/// and the content.
///
/// Note that the content may sometimes not match the header tag (for ex when parsing IMPLICIT
/// tagged values).
#[derive(Drop, Clone)]
pub struct BerObject {
    pub header: Header,
    pub content: BerObjectContent,
}

/// BER object content
#[derive(Drop, Clone)]
pub enum BerObjectContent {
    /// BOOLEAN: decoded value
    Boolean: bool,
    /// INTEGER: raw bytes
    ///
    /// Note: the reason to store the raw bytes is that integers have non-finite length in the
    /// spec, and also that the raw encoding is also important for some applications.
    ///
    /// To extract the number, see the `as_u64`, `as_u32`, `as_bigint` and `as_biguint` methods.
    Integer: @Span<u8>,
    /// SEQUENCE: list of objects
    Sequence: Array<BerObject>,
    /// Private or Unknown (for ex. unknown tag) object
    Unknown: Any,
}

#[generate_trait]
pub impl BerObjectImpl of BerObjectTrait {
    /// Build a BerObject from a header and content.
    ///
    /// Note: values are not checked, so the tag can be different from the real content, or flags
    /// can be invalid.
    #[inline]
    const fn from_header_and_content(header: Header, content: BerObjectContent) -> BerObject {
        BerObject { header, content }
    }

    /// Attempt to read integer value from DER object.
    fn as_u32(self: @BerObject) -> Result<u32, BerError> {
        self.content.as_u32()
    }

    /// Attempt to read integer value from DER object.
    /// This can fail if the object is not a boolean.
    fn as_bool(self: @BerObject) -> Result<bool, BerError> {
        self.content.as_bool()
    }

    /// Attempt to extract the list of objects from a DER sequence.
    /// This can fail if the object is not a sequence.
    fn as_sequence(self: BerObject) -> Result<Array<BerObject>, BerError> {
        self.content.as_sequence()
    }
}

#[generate_trait]
pub impl BerObjectContentImpl of BerObjectContentTrait {
    /// Attempt to read integer value from this object.
    ///
    /// This can fail if the object is not an unsigned integer, or if it is too large.
    fn as_u32(self: @BerObjectContent) -> Result<u32, BerError> {
        match self {
            BerObjectContent::Integer(i) => {
                let result = U32FromBeBytes::from_be_bytes(decode_array_uint4(*i)?);
                Ok(result)
            },
            _ => Err(BerError::BerTypeError),
        }
    }

    fn as_bool(self: @BerObjectContent) -> Result<bool, BerError> {
        match self {
            BerObjectContent::Boolean(b) => Ok(*b),
            _ => Err(BerError::BerTypeError),
        }
    }

    fn as_sequence(self: BerObjectContent) -> Result<Array<BerObject>, BerError> {
        match self {
            BerObjectContent::Sequence(s) => Ok(s),
            _ => Err(BerError::BerTypeError),
        }
    }
}
