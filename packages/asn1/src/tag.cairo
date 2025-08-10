use crate::{Error, InvalidValue, UnexpectedTag};

/// BER/DER Tag as defined in X.680 section 8.4
///
/// X.690 doesn't specify the maximum tag size so we're assuming that people
/// aren't going to need anything more than a u32.
#[derive(Drop, Debug, Copy, PartialEq)]
pub struct Tag {
    pub tag: u32,
}

pub const TAG_ENDOFCONTENT: Tag = Tag { tag: 0 };
pub const TAG_BOOLEAN: Tag = Tag { tag: 1 };
pub const TAG_INTEGER: Tag = Tag { tag: 2 };
pub const TAG_BITSTRING: Tag = Tag { tag: 3 };
pub const TAG_OCTETSTRING: Tag = Tag { tag: 4 };
pub const TAG_OBJECTDESCRIPTOR: Tag = Tag { tag: 7 };
pub const TAG_ENUMERATED: Tag = Tag { tag: 10 };
pub const TAG_UTF8STRING: Tag = Tag { tag: 12 };
pub const TAG_SEQUENCE: Tag = Tag { tag: 16 };
pub const TAG_SET: Tag = Tag { tag: 17 };
pub const TAG_NUMERICSTRING: Tag = Tag { tag: 18 };
pub const TAG_PRINTABLESTRING: Tag = Tag { tag: 19 };
pub const TAG_T61STRING: Tag = Tag { tag: 20 };
pub const TAG_VIDEOTEXSTRING: Tag = Tag { tag: 21 };
pub const TAG_IA5STRING: Tag = Tag { tag: 22 };
pub const TAG_UTCTIME: Tag = Tag { tag: 23 };
pub const TAG_GENERALIZEDTIME: Tag = Tag { tag: 24 };
pub const TAG_GRAPHICSTRING: Tag = Tag { tag: 25 };
pub const TAG_VISIBLESTRING: Tag = Tag { tag: 26 };
pub const TAG_GENERALSTRING: Tag = Tag { tag: 27 };
pub const TAG_UNIVERSALSTRING: Tag = Tag { tag: 28 };
pub const TAG_BMPSTRING: Tag = Tag { tag: 30 };

#[generate_trait]
pub impl TagImpl of TagTrait {
    const fn assert_eq(self: @Tag, tag: Tag) -> Result<(), Error> {
        if *self.tag == tag.tag {
            Ok(())
        } else {
            Err(Error::UnexpectedTag(UnexpectedTag { expected: Some(tag), actual: *self }))
        }
    }

    fn invalid_value(self: @Tag, msg: ByteArray) -> Error {
        Error::InvalidValue(InvalidValue { tag: *self, msg })
    }
}

pub impl U32IntoTag of Into<u32, Tag> {
    fn into(self: u32) -> Tag {
        Tag { tag: self }
    }
}
