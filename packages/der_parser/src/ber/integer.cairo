use crate::error::*;

/// Decode an unsigned integer into a big endian byte slice with all leading
/// zeroes removed.
///
/// Returns a byte array of the requested size containing a big endian integer.
fn remove_zeroes(bytes: @Span<u8>) -> Result<@Span<u8>, BerError> {
    // skip leading 0s
    // CAIRO: Rewrote pattern matching using span operations.
    if bytes.is_empty() {
        return Ok(bytes);
    }
    if bytes.len() == 1 && *bytes[0] == 0 {
        // [] => Err(BerError::DerConstraintFailed),
        return Ok(bytes);
    }
    if *bytes[0] == 0 {
        // [0, byte, ..] if *byte < 0x80 => Err(BerError::DerConstraintFailed),
        // [0, rest @ ..] => Ok(&rest),
        let rest = @bytes.slice(1, bytes.len() - 1);
        return remove_zeroes(rest);
    }
    // [byte, ..] if *byte >= 0x80 => Err(BerError::IntegerTooLarge),
    Ok(bytes)
}

pub(crate) fn decode_array_uint4(bytes: @Span<u8>) -> Result<[u8; 4], BerError> {
    // Check if MSB is set *before* leading zeroes
    if is_highest_bit_set(bytes) {
        return Result::Err(BerError::IntegerNegative);
    }
    let input = remove_zeroes(bytes)?;

    if input.len() > 4 {
        return Result::Err(BerError::IntegerTooLarge);
    }

    // Input has leading zeroes removed, so we need to add them back
    // CAIRO: Rewrote copy_from_slice and array initialization.
    let mut output = array![];
    assert!(input.len() <= 4);
    let offset = 4_usize - input.len();
    for _ in 0..offset {
        output.append(0);
    }
    for i in 0..input.len() {
        output.append(*input[i]);
    }
    Ok([*output[0], *output[1], *output[2], *output[3]])
}

// CAIRO: Rewrote using Span API.
//
/// Is the highest bit of the first byte in the slice 1? (if present)
#[inline]
pub(crate) fn is_highest_bit_set(bytes: @Span<u8>) -> bool {
    if bytes.is_empty() {
        false
    } else {
        let byte = *bytes[0];
        byte & 0b1000_0000 != 0
    }
}
