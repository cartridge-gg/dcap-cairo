use crate::error::DerConstraint;
use crate::{
    Any, AnyTrait, CheckDerConstraints, Error, FromDer, Header, HeaderTrait, TAG_BITSTRING, Tag,
    TagTrait, Tagged,
};

/// ASN.1 `BITSTRING` type
#[derive(Clone, Drop, Debug)]
pub struct BitString {
    pub unused_bits: u8,
    pub data: Span<u8>,
}

pub impl AnyTryIntoBitString of Into<Any, Result<BitString, Error>> {
    fn into(self: Any) -> Result<BitString, Error> {
        self.tag().assert_eq(BitStringTagged::TAG)?;
        if self.data.is_empty() {
            return Result::Err(Error::InvalidLength);
        }
        let s = self.data;
        let mut data_slice = s.clone();
        let unused_bits = *data_slice.pop_front().unwrap();
        Ok(BitString { unused_bits, data: data_slice })
    }
}

impl BitStringCheckDerConstraints of CheckDerConstraints<BitString> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        // X.690 section 10.2
        any.header.assert_primitive()?;
        // Check that padding bits are all 0 (X.690 section 11.2.1)
        match (*any.data).len() {
            0 => Result::Err(Error::InvalidLength),
            1 => {
                // X.690 section 11.2.2 Note 2
                if *((*any.data)[0]) == 0 {
                    Ok(())
                } else {
                    Result::Err(Error::InvalidLength)
                }
            },
            _ => {
                let len = (*any.data).len();
                let unused_bits = *((*any.data)[0]);
                let last_byte = *((*any.data)[len - 1]);
                // We need to verify that the last `unused_bits` bits are all zero
                if unused_bits > 0 {
                    // Create a mask for the unused bits (they should all be 0)
                    // For example, if unused_bits = 3, mask = 0b00000111
                    let mask = if unused_bits == 1 {
                        0b00000001_u8
                    } else if unused_bits == 2 {
                        0b00000011_u8
                    } else if unused_bits == 3 {
                        0b00000111_u8
                    } else if unused_bits == 4 {
                        0b00001111_u8
                    } else if unused_bits == 5 {
                        0b00011111_u8
                    } else if unused_bits == 6 {
                        0b00111111_u8
                    } else if unused_bits == 7 {
                        0b01111111_u8
                    } else {
                        0_u8
                    };
                    if (last_byte & mask) != 0 {
                        return Result::Err(
                            Error::DerConstraintFailed(DerConstraint::UnusedBitsNotZero),
                        );
                    }
                }

                Ok(())
            },
        }
    }
}

pub impl BitStringTagged of Tagged<BitString> {
    const TAG: Tag = TAG_BITSTRING;
}
