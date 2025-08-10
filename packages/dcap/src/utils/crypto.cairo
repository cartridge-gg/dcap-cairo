use starknet::secp256_trait::is_valid_signature;

// CAIRO: Extra module to handle value decoding. In Rust this is done with the `p256` and `ecdsa`
//        crates. Here we deviate from this structure as the majority of the ECDSA support comes
//        from the `starknet` module.
pub mod p256;
use p256::{
    compute_digest, compute_digest_ba, decode_der_signature, decode_public_key,
    decode_sec1_public_key, decode_signature,
};

// verify_p256_signature_bytes verifies a P256 ECDSA signature
// using the provided data, signature, and public key.
// The data is the message that was signed as a byte slice.
// The signature is the signature (in raw form [r][s]) of the data as a byte slice. (64 bytes)
// The public_key is the public key (in uncompressed form [4][x][y]) of the entity that signed the
// data. (65 bytes)
// Returns true if the signature is valid, false otherwise.
pub fn verify_p256_signature_bytes(
    data: @ByteArray, signature: @Span<u8>, public_key: @Span<u8>,
) -> bool {
    let (r, s) = decode_signature(signature);
    let verifying_key = decode_sec1_public_key(public_key);
    is_valid_signature(compute_digest_ba(data), r, s, verifying_key)
}

// CAIRO: Added extra function for taking `data` as `@Span<u8>`.
pub fn verify_p256_signature_bytes_span(
    data: @Span<u8>, signature: @Span<u8>, public_key: @Span<u8>,
) -> bool {
    let (r, s) = decode_signature(signature);
    let verifying_key = decode_sec1_public_key(public_key);
    is_valid_signature(compute_digest(data), r, s, verifying_key)
}

// CAIRO: Added extra function for taking `data` as `@Span<u8>` and `public_key` without SEC1
// prefix.
pub fn verify_p256_signature_bytes_span_no_pk_prefix(
    data: @Span<u8>, signature: @Span<u8>, public_key: @Span<u8>,
) -> bool {
    let (r, s) = decode_signature(signature);
    let verifying_key = decode_public_key(public_key);
    is_valid_signature(compute_digest(data), r, s, verifying_key)
}

pub fn verify_p256_signature_der(
    data: @Span<u8>, signature: @Span<u8>, public_key: @Span<u8>,
) -> bool {
    let (_, (r, s)) = decode_der_signature(signature).unwrap();
    let verifying_key = decode_sec1_public_key(public_key);
    is_valid_signature(compute_digest(data), r, s, verifying_key)
}
