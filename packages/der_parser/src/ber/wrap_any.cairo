use asn1::*;
use nom::{Err, NeededTrait};
use crate::ber::{MAX_OBJECT_SIZE, ber_get_object_content};
use crate::error::BerResult;
use super::{BerObject, BerObjectContent, BerObjectTrait};

/// Read element content as Universal object, or Unknown
// TODO implement the function for BerObjectContent (to replace ber_read_element_content_as)
// note: we cannot implement TryFrom because of the `max_depth` argument
pub(crate) fn try_read_berobjectcontent_as(
    i: @Span<u8>, tag: Tag, length: Length, constructed: bool, max_depth: usize,
) -> BerResult<BerObjectContent> {
    if let Length::Definite(l) = length {
        if l > MAX_OBJECT_SIZE {
            return Result::Err(Err::Error(Error::InvalidLength));
        }
        if i.len() < l {
            return Result::Err(Err::Incomplete(NeededTrait::new(l)));
        }
    }
    let header = HeaderTrait::new(Class::Universal, constructed, tag, length);
    let (rem, i) = ber_get_object_content(i, @header, max_depth)?;
    let any = AnyTrait::new(header, i);
    let object = try_berobject_from_any(any, max_depth).map_err(|err| err.into())?;
    Ok((rem, object.content))
}

// note: we cannot implement TryFrom because of the `max_depth` argument
fn try_berobject_from_any(any: Any, max_depth: usize) -> Result<BerObject, Error> {
    if max_depth == 0 {
        return Result::Err(Error::InvalidLength);
    }
    let header = any.header.clone();
    if *any.class() != Class::Universal {
        return Ok(BerObjectTrait::from_header_and_content(header, BerObjectContent::Unknown(any)));
    }

    // CAIRO: Rewrote match as if chain.
    if *any.tag() == TAG_BOOLEAN {
        let b = Into::<Any, Result<bool, Error>>::into(any)?;
        Ok(BerObjectTrait::from_header_and_content(header, BerObjectContent::Boolean(b)))
    } else if *any.tag() == TAG_INTEGER {
        Ok(BerObjectTrait::from_header_and_content(header, BerObjectContent::Integer(any.data)))
    } else if *any.tag() == TAG_SEQUENCE {
        header.assert_constructed()?;
        let mut objects = array![];
        let mut iter = SequenceIteratorTrait::<Any, BerParser, Error>::new(any.data);
        // CAIRO: Rewrote iter mapping.
        loop {
            match iter.next() {
                Some(item) => {
                    match item {
                        Ok(item) => {
                            let object = match try_berobject_from_any(item, max_depth - 1) {
                                Ok(object) => object,
                                Result::Err(err) => { break Result::Err(err); },
                            };
                            objects.append(object);
                        },
                        Result::Err(err) => { break Result::Err(err); },
                    }
                },
                None => { break Ok(()); },
            }
        }?;
        Ok(BerObjectTrait::from_header_and_content(header, BerObjectContent::Sequence(objects)))
    } else {
        panic!("TODO: tag type not implemented: {:?}", any.tag())
    }
}
