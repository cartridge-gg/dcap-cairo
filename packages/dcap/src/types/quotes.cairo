use core::array::SpanTrait;
use core::traits::Into;
use int_traits::{U16FromLeBytes, U16ToLeBytes, U32FromLeBytes, U32ToLeBytes};

pub mod body;
pub mod version_4;
use body::EnclaveReport;

#[derive(Drop, Debug)]
pub struct QuoteHeader {
    pub version: u16, // [2 bytes]
    // Version of the quote data structure - 4, 5
    pub att_key_type: u16, // [2 bytes]
    // Type of the Attestation Key used by the Quoting Enclave -
    // 2 (ECDSA-256-with-P-256 curve)
    // 3 (ECDSA-384-with-P-384 curve)
    pub tee_type: u32, // [4 bytes]
    // TEE for this Attestation
    // 0x00000000: SGX
    // 0x00000081: TDX
    pub qe_svn: [u8; 2], // [2 bytes]
    // Security Version of the Quoting Enclave - 1 (only applicable for SGX Quotes)
    pub pce_svn: [u8; 2], // [2 bytes]
    // Security Version of the PCE - 0 (only applicable for SGX Quotes)
    pub qe_vendor_id: [u8; 16], // [16 bytes]
    // Unique identifier of the QE Vendor.
    // Value: 939A7233F79C4CA9940A0DB3957F0607 (Intel® SGX QE Vendor)
    // Note: Each vendor that decides to provide a customized Quote data structure should have
    // unique ID.
    // CAIRO: Using Array<u8> instead of [u8; 20] because Cairo lacks built-in trait implementations
    // for arrays of size 20
    pub user_data: Array<u8> // [20 bytes]
}

#[generate_trait]
pub impl QuoteHeaderImpl of QuoteHeaderTrait {
    fn from_bytes(bytes: Span<u8>) -> QuoteHeader {
        // version (2 bytes)
        let version = U16FromLeBytes::from_le_bytes([*bytes[0], *bytes[1]]);

        // att_key_type (2 bytes)
        let att_key_type = U16FromLeBytes::from_le_bytes([*bytes[2], *bytes[3]]);

        // tee_type (4 bytes)
        let tee_type = U32FromLeBytes::from_le_bytes([*bytes[4], *bytes[5], *bytes[6], *bytes[7]]);

        // qe_svn (2 bytes)
        let qe_svn = [*bytes[8], *bytes[9]];

        // pce_svn (2 bytes)
        let pce_svn = [*bytes[10], *bytes[11]];

        // qe_vendor_id (16 bytes)
        let qe_vendor_id = [
            *bytes[12], *bytes[13], *bytes[14], *bytes[15], *bytes[16], *bytes[17], *bytes[18],
            *bytes[19], *bytes[20], *bytes[21], *bytes[22], *bytes[23], *bytes[24], *bytes[25],
            *bytes[26], *bytes[27],
        ];

        // user_data (20 bytes)
        let user_data: Array<u8> = bytes.slice(28, 20).into();

        QuoteHeader { version, att_key_type, tee_type, qe_svn, pce_svn, qe_vendor_id, user_data }
    }

    fn to_bytes(self: @QuoteHeader) -> Array<u8> {
        let mut raw_bytes = array![];
        raw_bytes.append_span(self.version.to_le_bytes().span());
        raw_bytes.append_span(self.att_key_type.to_le_bytes().span());
        raw_bytes.append_span(self.tee_type.to_le_bytes().span());
        raw_bytes.append_span(self.qe_svn.span());
        raw_bytes.append_span(self.pce_svn.span());
        raw_bytes.append_span(self.qe_vendor_id.span());
        raw_bytes.append_span(self.user_data.span());

        raw_bytes
    }
}

#[derive(Drop, Debug)]
pub struct QeAuthData {
    pub size: u16,
    pub data: Array<u8>,
}

#[generate_trait]
pub impl QeAuthDataImpl of QeAuthDataTrait {
    fn from_bytes(bytes: Span<u8>) -> QeAuthData {
        let size = U16FromLeBytes::from_le_bytes([*bytes[0], *bytes[1]]);
        let size_usize: usize = size.into();
        let data: Array<u8> = bytes.slice(2, size_usize).into();
        QeAuthData { size, data }
    }
}

#[derive(Drop, Debug)]
pub struct CertData {
    pub cert_data_type: u16,
    pub cert_data_size: u32,
    pub cert_data: Array<u8>,
}

#[generate_trait]
pub impl CertDataImpl of CertDataTrait {
    fn from_bytes(bytes: Span<u8>) -> CertData {
        // cert_data_type (2 bytes)
        let cert_data_type = U16FromLeBytes::from_le_bytes([*bytes[0], *bytes[1]]);

        // cert_data_size (4 bytes)
        let cert_data_size = U32FromLeBytes::from_le_bytes(
            [*bytes[2], *bytes[3], *bytes[4], *bytes[5]],
        );

        // cert_data
        let cert_data_size_usize: usize = cert_data_size.into();
        let cert_data: Array<u8> = bytes.slice(6, cert_data_size_usize).into();

        CertData { cert_data_type, cert_data_size, cert_data }
    }

    // CAIRO: Using if-else chain instead of match because Cairo requires sequential numbers
    // starting from 0 in match statements
    fn get_cert_data(self: @CertData) -> CertDataType {
        if *self.cert_data_type == 1 {
            CertDataType::Type1(self.cert_data.clone())
        } else if *self.cert_data_type == 2 {
            CertDataType::Type2(self.cert_data.clone())
        } else if *self.cert_data_type == 3 {
            CertDataType::Type3(self.cert_data.clone())
        } else if *self.cert_data_type == 4 {
            CertDataType::Type4(self.cert_data.clone())
        } else if *self.cert_data_type == 5 {
            panic!("TODO: CertDataType::CertChain")
        } else if *self.cert_data_type == 6 {
            CertDataType::QeReportCertData(QeReportCertDataTrait::from_bytes(self.cert_data.span()))
        } else if *self.cert_data_type == 7 {
            CertDataType::Type7(self.cert_data.clone())
        } else {
            CertDataType::Unused
        }
    }
}

#[derive(Drop, Debug)]
pub enum CertDataType {
    Unused,
    Type1: Array<u8>,
    Type2: Array<u8>,
    Type3: Array<u8>,
    Type4: Array<u8>,
    // CertChain would go here but is TODO
    QeReportCertData: QeReportCertData,
    Type7: Array<u8>,
}

#[derive(Drop, Debug)]
pub struct QeReportCertData {
    pub qe_report: EnclaveReport,
    // CAIRO: Using Array<u8> instead of [u8; 64] because Cairo lacks built-in trait implementations
    // for arrays of size 64
    pub qe_report_signature: Array<u8>,
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

#[generate_trait]
pub impl QeReportCertDataImpl of QeReportCertDataTrait {
    fn from_bytes(bytes: Span<u8>) -> QeReportCertData {
        // 384 bytes for qe_report
        let qe_report = body::EnclaveReportTrait::from_bytes(bytes.slice(0, 384));
        // 64 bytes for qe_report_signature
        let qe_report_signature: Array<u8> = bytes.slice(384, 64).into();
        // qe auth data is variable length, we'll pass remaining bytes to the from_bytes method
        let qe_auth_data = QeAuthDataTrait::from_bytes(bytes.slice(448, bytes.len() - 448));
        // get the length of qe_auth_data
        let qe_auth_data_size = 2 + qe_auth_data.size;
        // finish off with the parsing of qe_cert_data
        let qe_cert_data_start: usize = 448 + qe_auth_data_size.into();
        let qe_cert_data = CertDataTrait::from_bytes(
            bytes.slice(qe_cert_data_start, bytes.len() - qe_cert_data_start),
        );

        QeReportCertData { qe_report, qe_report_signature, qe_auth_data, qe_cert_data }
    }
}
