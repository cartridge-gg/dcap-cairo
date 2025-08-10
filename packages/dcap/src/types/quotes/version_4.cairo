use core::array::SpanTrait;
use core::traits::Into;
use int_traits::U32FromLeBytes;
use crate::constants::{HEADER_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE};
use crate::types::quotes::body::{QuoteBody, TD10ReportBodyTrait};
use crate::types::quotes::{CertData, CertDataTrait, QuoteHeader, QuoteHeaderTrait};

#[derive(Drop, Debug)]
pub struct QuoteV4 {
    pub header: QuoteHeader,
    pub quote_body: QuoteBody,
    pub signature_len: u32,
    pub signature: QuoteSignatureDataV4,
}

#[generate_trait]
pub impl QuoteV4Impl of QuoteV4Trait {
    fn from_bytes(bytes: Span<u8>) -> QuoteV4 {
        let header = QuoteHeaderTrait::from_bytes(bytes.slice(0, HEADER_LEN));

        let mut offset: usize = 48;
        let quote_body = if header.tee_type == TDX_TEE_TYPE {
            offset += TD10_REPORT_LEN;
            QuoteBody::TD10QuoteBody(
                TD10ReportBodyTrait::from_bytes(bytes.slice(HEADER_LEN, TD10_REPORT_LEN)),
            )
        } else if header.tee_type == SGX_TEE_TYPE {
            // CAIRO: TODO panic for SGX quotes - only TDX is implemented
            panic!("TODO: QuoteV4Trait::from_bytes - SGX quote parsing not implemented")
        } else {
            panic!("Unknown TEE type")
        };
        let signature_len = U32FromLeBytes::from_le_bytes(
            [*bytes[offset], *bytes[offset + 1], *bytes[offset + 2], *bytes[offset + 3]],
        );
        offset += 4;
        let signature = QuoteSignatureDataV4Trait::from_bytes(
            bytes.slice(offset, signature_len.into()),
        );

        QuoteV4 { header, quote_body, signature_len, signature }
    }
}

#[derive(Drop, Debug)]
pub struct QuoteSignatureDataV4 {
    pub quote_signature: Array<u8>,
    pub ecdsa_attestation_key: Array<u8>,
    pub qe_cert_data: CertData,
}

#[generate_trait]
pub impl QuoteSignatureDataV4Impl of QuoteSignatureDataV4Trait {
    fn from_bytes(bytes: Span<u8>) -> QuoteSignatureDataV4 {
        // quote_signature (64 bytes)
        let quote_signature: Array<u8> = bytes.slice(0, 64).into();

        // ecdsa_attestation_key (64 bytes)
        let ecdsa_attestation_key: Array<u8> = bytes.slice(64, 64).into();

        // qe_cert_data
        let qe_cert_data = CertDataTrait::from_bytes(bytes.slice(128, bytes.len() - 128));

        QuoteSignatureDataV4 { quote_signature, ecdsa_attestation_key, qe_cert_data }
    }
}
