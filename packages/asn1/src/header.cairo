use nom::bytes::streaming::take;
use crate::ber::*;
use crate::error::*;
use crate::{Class, FromBer, FromDer, Length, Tag, TagTrait};

/// BER/DER object header (identifier and length)
#[derive(Drop, Debug, Clone, PartialEq)]
pub struct Header {
    /// Object class: universal, application, context-specific, or private
    pub(crate) class: Class,
    /// Constructed attribute: true if constructed, else false
    pub(crate) constructed: bool,
    /// Tag number
    pub(crate) tag: Tag,
    /// Object length: value if definite, or indefinite
    pub(crate) length: Length,
    /// Optionally, the raw encoding of the tag
    ///
    /// This is useful in some cases, where different representations of the same
    /// BER tags have different meanings (BER only)
    pub(crate) raw_tag: Option<@Span<u8>>,
}

#[generate_trait]
pub impl HeaderImpl of HeaderTrait {
    fn new(class: Class, constructed: bool, tag: Tag, length: Length) -> Header {
        Header { tag, constructed, class, length, raw_tag: None }
    }

    /// Update header to add reference to raw tag
    #[inline]
    fn with_raw_tag(self: Header, raw_tag: Option<@Span<u8>>) -> Header {
        Header { raw_tag, ..self }
    }

    /// Return the class of this header.
    #[inline]
    const fn class(self: @Header) -> @Class {
        self.class
    }

    /// Return the tag of this header.
    #[inline]
    const fn tag(self: @Header) -> @Tag {
        self.tag
    }

    /// Return the length of this header.
    #[inline]
    const fn length(self: @Header) -> @Length {
        self.length
    }

    /// Test if object is primitive.
    #[inline]
    const fn is_primitive(self: @Header) -> bool {
        !*self.constructed
    }

    /// Test if object is constructed
    #[inline]
    const fn is_constructed(self: @Header) -> bool {
        *self.constructed
    }

    /// Return error if tag is not the expected tag
    #[inline]
    const fn assert_tag(self: @Header, tag: Tag) -> Result<(), Error> {
        self.tag.assert_eq(tag)
    }

    /// Return error if object is not primitive
    #[inline]
    const fn assert_primitive(self: @Header) -> Result<(), Error> {
        if self.is_primitive() {
            Ok(())
        } else {
            Err(Error::ConstructUnexpected)
        }
    }

    /// Return error if object is primitive
    #[inline]
    const fn assert_constructed(self: @Header) -> Result<(), Error> {
        if !self.is_primitive() {
            Ok(())
        } else {
            Err(Error::ConstructExpected)
        }
    }
}

pub impl HeaderFromBer of FromBer<Header, Error> {
    fn from_ber(bytes: @Span<u8>) -> ParseResult<Header, Error> {
        let (i1, el) = parse_identifier(bytes)?;
        let (el0, el1, el2, el3) = el;

        // Cannot fail, we have read exactly 2 bits
        let class = TryInto::<u8, Class>::try_into(el0).unwrap();
        let (i2, len) = parse_ber_length_byte(i1)?;
        let (len0, len1) = len;

        // CAIRO: Rewrote `match` into `if` chain.
        let (i3, len) = if len0 == 0 {
            // Short form: MSB is 0, the rest encodes the length (which can be 0) (8.1.3.4)
            (i2, Length::Definite(len1.into()))
        } else if len1 == 0 {
            // Indefinite form: MSB is 1, the rest is 0 (8.1.3.6)
            // If encoding is primitive, definite form shall be used (8.1.3.2)
            if el1 == 0 {
                return Err(nom::Err::Error(Error::ConstructExpected));
            }
            (i2, Length::Indefinite)
        } else {
            // if len is 0xff -> error (8.1.3.5)
            if len1 == 0b0111_1111 {
                return Err(nom::Err::Error(Error::InvalidLength));
            }
            let (i3, llen) = take(len1, i2)?;
            match bytes_to_u64(llen) {
                Ok(l) => {
                    let l = TryInto::<_, usize>::try_into(l)
                        .ok_or(nom::Err::Error(Error::InvalidLength))?;
                    (i3, Length::Definite(l))
                },
                Err(_) => { return Err(nom::Err::Error(Error::InvalidLength)); },
            }
        };
        let constructed = el1 != 0;
        let hdr = HeaderImpl::new(class, constructed, Tag { tag: el2 }, len)
            .with_raw_tag(Some(el3.into()));
        Ok((i3, hdr))
    }
}

pub impl HeaderFromDer of FromDer<Header, Error> {
    fn from_der(bytes: @Span<u8>) -> ParseResult<Header, Error> {
        let (i1, el) = parse_identifier(bytes)?;
        let (el0, el1, el2, el3) = el;

        // Cannot fail, we have read exactly 2 bits
        let class = TryInto::<_, Class>::try_into(el0).unwrap();
        let (i2, len) = parse_ber_length_byte(i1)?;
        let (len0, len1) = len;

        // CAIRO: Rewrote `match` as `if` chain due to supported lang feature
        let (i3, len) = if len0 == 0 {
            // Short form: MSB is 0, the rest encodes the length (which can be 0) (8.1.3.4)
            (i2, Length::Definite(len1.into()))
        } else if len1 == 0 {
            // Indefinite form is not allowed in DER (10.1)
            return Err(
                nom::Err::Error(Error::DerConstraintFailed(DerConstraint::IndefiniteLength)),
            );
        } else {
            // if len is 0xff -> error (8.1.3.5)
            if len1 == 0b0111_1111 {
                return Err(nom::Err::Error(Error::InvalidLength));
            }
            // DER(9.1) if len is 0 (indefinite form), obj must be constructed
            if len1 == 0 && el1 != 1 {
                return Err(
                    nom::Err::Error(Error::DerConstraintFailed(DerConstraint::NotConstructed)),
                );
            }
            let (i3, llen) = take(len1, i2)?;
            match bytes_to_u64(llen) {
                Ok(l) => {
                    // DER: should have been encoded in short form (< 127)
                    // XXX der_constraint_fail_if!(i, l < 127);
                    let l = TryInto::<_, usize>::try_into(l)
                        .ok_or(nom::Err::Error(Error::InvalidLength))?;
                    (i3, Length::Definite(l))
                },
                Err(_) => { return Err(nom::Err::Error(Error::InvalidLength)); },
            }
        };
        let constructed = el1 != 0;
        let hdr = HeaderImpl::new(class, constructed, Tag { tag: el2 }, len)
            .with_raw_tag(Some(el3.into()));

        Ok((i3, hdr))
    }
}
