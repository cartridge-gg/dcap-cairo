use asn1::{Any, AnyTrait, FromDer, Header, HeaderTrait, TAG_INTEGER, TAG_SEQUENCE, TagTrait};
use core::sha256::compute_sha256_byte_array;
use der_parser::error::BerResult;
use int_traits::U256FromBytesBe;
use starknet::secp256_trait::Secp256Trait;
use starknet::secp256r1::Secp256r1Point;

const SEC1_TAG_UNCOMPRESSED: u8 = 4;

/// Parse a signature from fixed-width bytes, i.e. 2 * the size of
/// [`FieldBytes`] for a particular curve.
///
/// # Returns
/// - `Ok(signature)` if the `r` and `s` components are both in the valid
///   range `1..n` when serialized as concatenated big endian integers.
/// - `Err(err)` if the `r` and/or `s` component of the signature is
///   out-of-range when interpreted as a big endian integer.
pub(crate) fn decode_signature(bytes: @Span<u8>) -> (u256, u256) {
    assert!(bytes.len() == 64);

    let r = U256FromBytesBe::from_be_byte_span(@bytes.slice(0, 32));
    let s = U256FromBytesBe::from_be_byte_span(@bytes.slice(32, 32));

    (r, s)
}

/// Decodes the `r` and `s` components of a DER-encoded ECDSA signature.
pub(crate) fn decode_der_signature(der_bytes: @Span<u8>) -> BerResult<(u256, u256)> {
    let (i, header) = FromDer::<Header>::from_der(der_bytes)?;
    header.assert_tag(TAG_SEQUENCE).map_err(|err| err.into())?;

    let (i, r) = decode_u256_der(i)?;
    let (i, s) = decode_u256_der(i)?;

    Ok((i, (r, s)))
}

pub(crate) fn decode_sec1_public_key(bytes: @Span<u8>) -> Secp256r1Point {
    // Only support uncompressed SEC1 encoding for now
    assert!(bytes.len() == 65);
    assert!(*bytes.at(0) == SEC1_TAG_UNCOMPRESSED);

    let x = U256FromBytesBe::from_be_byte_span(@bytes.slice(1, 32));
    let y = U256FromBytesBe::from_be_byte_span(@bytes.slice(33, 32));

    Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(x, y).unwrap().unwrap()
}

// CAIRO: Additional variant for decoding non-prefixed keys.
pub(crate) fn decode_public_key(bytes: @Span<u8>) -> Secp256r1Point {
    assert!(bytes.len() == 64);

    let x = U256FromBytesBe::from_be_byte_span(@bytes.slice(0, 32));
    let y = U256FromBytesBe::from_be_byte_span(@bytes.slice(32, 32));

    Secp256Trait::<Secp256r1Point>::secp256_ec_new_syscall(x, y).unwrap().unwrap()
}

pub(crate) fn compute_digest(data: @Span<u8>) -> u256 {
    let mut ba = Default::<ByteArray>::default();
    for byte in data {
        ba.append_byte(*byte);
    }

    let hash_result = compute_sha256_byte_array(@ba);
    let mut digest: u256 = 0;
    for word in hash_result.span() {
        digest *= 0x100000000;
        digest = digest + (*word).into();
    }
    digest
}

pub(crate) fn compute_digest_ba(data: @ByteArray) -> u256 {
    let hash_result = compute_sha256_byte_array(data);
    let mut digest: u256 = 0;
    for word in hash_result.span() {
        digest *= 0x100000000;
        digest = digest + (*word).into();
    }
    digest
}

/// Parses a DER-encoded `u256` value.
fn decode_u256_der(i: @Span<u8>) -> BerResult<u256> {
    let (i, any) = FromDer::<Any>::from_der(i)?;
    any.tag().assert_eq(TAG_INTEGER).map_err(|err| err.into())?;

    // Handle leading zeros
    let data = if any.data.len() > 32 {
        let start_index = any.data.len() - 32;

        // No big-int support
        for element in any.data.slice(0, start_index) {
            assert!(element == @0);
        }

        @any.data.slice(start_index, 32)
    } else {
        any.data
    };

    Ok((i, U256FromBytesBe::from_be_byte_span(data)))
}
