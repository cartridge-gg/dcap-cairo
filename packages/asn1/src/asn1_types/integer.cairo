use int_traits::U32FromBeBytes;
use crate::*;

/// Decode an unsigned integer into a big endian byte slice with all leading
/// zeroes removed (if positive) and extra 0xff remove (if negative).
fn trim_slice(any: @Any) -> Result<@Span<u8>, Error> {
    let bytes = any.data;

    if bytes.is_empty() || (*bytes[0] != 0x00 && *bytes[0] != 0xff) {
        return Ok(*bytes);
    }

    let bytes_len = bytes.len();

    // CAIRO: Rewrite `.iter().position()`.
    let mut ind_first_non_zero_byte = None;
    for ind in 0..bytes_len {
        if *bytes[ind] != 0 {
            if ind == 0 {
                // first byte is not 0
                ind_first_non_zero_byte = Some(ind);
                break;
            } else {
                return Ok(@bytes.slice(ind, bytes_len - ind));
            }
        }
    }
    // all bytes are 0
    if ind_first_non_zero_byte.is_none() {
        return Ok(@bytes.slice(bytes_len - 1, 1));
    }

    // same for negative integers : skip byte 0->n if byte 0->n = 0xff AND byte n+1 >= 0x80
    // CAIRO: Rewrite `.window().position()`.
    for ind in 0..bytes_len {
        let is_non_0xff = if ind == bytes_len - 1 {
            // Window size = 1
            true
        } else {
            // Window size = 2
            let a = *bytes[ind];
            let b = *bytes[ind + 1];
            !(a == 0xff && b >= 0x80)
        };
        if is_non_0xff {
            if ind == 0 {
                // first byte is not 0xff
                return Ok(*bytes);
            } else {
                return Ok(@bytes.slice(ind, bytes_len - ind));
            }
        }
    }

    // all bytes are 0xff
    Ok(@bytes.slice(bytes.len() - 1, 1))
}

/// Decode an unsigned integer into a byte array of the requested size
/// containing a big endian integer.
fn decode_array_uint_4(any: @Any) -> Result<[u8; 4], Error> {
    if is_highest_bit_set(*any.data) {
        return Result::Err(Error::IntegerNegative);
    }
    let input = trim_slice(any)?;

    if input.len() > 4 {
        return Result::Err(Error::IntegerTooLarge);
    }

    // Input has leading zeroes removed, so we need to add them back
    // CAIRO: Rewrote `copy_from_slice`.
    let mut output = array![];
    assert!(input.len() <= 4);
    for _ in 0..(4 - input.len()) {
        output.append(0);
    }
    output.append_span(*input);

    Ok([*output[0], *output[1], *output[2], *output[3]])
}

/// Is the highest bit of the first byte in the slice 1? (if present)
#[inline]
fn is_highest_bit_set(bytes: @Span<u8>) -> bool {
    if bytes.is_empty() {
        false
    } else {
        let byte = *bytes[0];
        byte & 0b10000000 != 0
    }
}

pub impl U32Tagged of Tagged<u32> {
    const TAG: Tag = TAG_INTEGER;
}

pub impl AnyTryIntoU32 of Into<Any, Result<u32, Error>> {
    fn into(self: Any) -> Result<u32, Error> {
        self.tag().assert_eq(U32Tagged::TAG)?;
        self.header.assert_primitive()?;
        let result = U32FromBeBytes::from_be_bytes(decode_array_uint_4(@self)?);
        Ok(result)
    }
}

pub impl U32CheckDerConstraints of CheckDerConstraints<u32> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        check_der_int_constraints(any)
    }
}

fn check_der_int_constraints(any: @Any) -> Result<(), Error> {
    any.header.assert_primitive()?;
    any.header.length.assert_definite()?;

    // CAIRO: Rewrote `match` into `if` chain.
    let bytes = any.as_bytes();
    if bytes.is_empty() {
        Result::Err(Error::DerConstraintFailed(DerConstraint::IntegerEmpty))
    } else if bytes.len() == 1 && *bytes[0] == 0 {
        Ok(())
    } else if bytes.len() > 1 && *bytes[0] == 0 && *bytes[1] < 0x80 {
        // leading zeroes
        Result::Err(Error::DerConstraintFailed(DerConstraint::IntegerLeadingZeroes))
    } else if bytes.len() > 1 && *bytes[0] == 0xff && *bytes[1] >= 0x80 {
        // negative integer with non-minimal encoding
        Result::Err(Error::DerConstraintFailed(DerConstraint::IntegerLeadingFF))
    } else {
        Ok(())
    }
}
