use core::array::SpanTrait;
use int_traits::{U16FromLeBytes, U16ToLeBytes, U64FromLeBytes, U64ToLeBytes};

#[derive(Drop, Debug)]
pub enum QuoteBody {
    SGXQuoteBody: EnclaveReport,
    TD10QuoteBody: TD10ReportBody,
}

#[derive(Drop, Debug)]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16], // [16 bytes]
    // Security Version of the CPU (raw value)
    pub misc_select: [u8; 4], // [4 bytes]
    // SSA Frame extended feature set.
    // Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
    // allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    // CAIRO: Using Array<u8> instead of [u8; 28] because Cairo lacks built-in trait implementations
    // for arrays of size 28
    pub reserved_1: Array<u8>, // [28 bytes]
    // Reserved for future use - 0
    pub attributes: [u8; 16], // [16 bytes]
    // Set of flags describing attributes of the enclave.
    // Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
    // SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
    // The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK
    // which determine allowed ATTRIBUTES.
    // - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
    // SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    // CAIRO: Using Array<u8> instead of [u8; 32] because Cairo lacks built-in trait implementations
    // for arrays of size 32
    pub mrenclave: Array<u8>, // [32 bytes]
    // Measurement of the enclave.
    // The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    // CAIRO: Using Array<u8> instead of [u8; 32] because Cairo lacks built-in trait implementations
    // for arrays of size 32
    pub reserved_2: Array<u8>, // [32 bytes]
    // Reserved for future use - 0
    // CAIRO: Using Array<u8> instead of [u8; 32] because Cairo lacks built-in trait implementations
    // for arrays of size 32
    pub mrsigner: Array<u8>, // [32 bytes]
    // Measurement of the enclave signer.
    // The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    // CAIRO: Using Array<u8> instead of [u8; 96] because Cairo lacks built-in trait implementations
    // for arrays of size 96
    pub reserved_3: Array<u8>, // [96 bytes]
    // Reserved for future use - 0
    pub isv_prod_id: u16, // [2 bytes]
    // Product ID of the enclave.
    // The ISV should configure a unique ISVProdID for each product which may
    // want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
    // may want to supply different data to identical enclaves signed for different products.
    pub isv_svn: u16, // [2 bytes]
    // Security Version of the enclave
    // CAIRO: Using Array<u8> instead of [u8; 60] because Cairo lacks built-in trait implementations
    // for arrays of size 60
    pub reserved_4: Array<u8>, // [60 bytes]
    // Reserved for future use - 0
    // CAIRO: Using Array<u8> instead of [u8; 64] because Cairo lacks built-in trait implementations
    // for arrays of size 64
    pub report_data: Array<u8> // [64 bytes]
    // Additional report data.
// The enclave is free to provide 64 bytes of custom data to the REPORT.
// This can be used to provide specific data from the enclave or it can be used to hold
// a hash of a larger block of data which is provided with the quote.
// The verification of the quote signature confirms the integrity of the
// report data (and the rest of the REPORT body).
}

#[generate_trait]
pub impl EnclaveReportImpl of EnclaveReportTrait {
    fn from_bytes(bytes: Span<u8>) -> EnclaveReport {
        assert!(bytes.len() == 384, "EnclaveReport must be 384 bytes");

        // parse raw bytes into obj
        let cpu_svn = [
            *bytes[0], *bytes[1], *bytes[2], *bytes[3], *bytes[4], *bytes[5], *bytes[6], *bytes[7],
            *bytes[8], *bytes[9], *bytes[10], *bytes[11], *bytes[12], *bytes[13], *bytes[14],
            *bytes[15],
        ];
        let misc_select = [*bytes[16], *bytes[17], *bytes[18], *bytes[19]];
        let reserved_1: Array<u8> = bytes.slice(20, 28).into();
        let attributes = [
            *bytes[48], *bytes[49], *bytes[50], *bytes[51], *bytes[52], *bytes[53], *bytes[54],
            *bytes[55], *bytes[56], *bytes[57], *bytes[58], *bytes[59], *bytes[60], *bytes[61],
            *bytes[62], *bytes[63],
        ];
        let mrenclave: Array<u8> = bytes.slice(64, 32).into();
        let reserved_2: Array<u8> = bytes.slice(96, 32).into();
        let mrsigner: Array<u8> = bytes.slice(128, 32).into();
        let reserved_3: Array<u8> = bytes.slice(160, 96).into();
        let isv_prod_id = U16FromLeBytes::from_le_bytes([*bytes[256], *bytes[257]]);
        let isv_svn = U16FromLeBytes::from_le_bytes([*bytes[258], *bytes[259]]);
        let reserved_4: Array<u8> = bytes.slice(260, 60).into();
        let report_data: Array<u8> = bytes.slice(320, 64).into();

        EnclaveReport {
            cpu_svn,
            misc_select,
            reserved_1,
            attributes,
            mrenclave,
            reserved_2,
            mrsigner,
            reserved_3,
            isv_prod_id,
            isv_svn,
            reserved_4,
            report_data,
        }
    }

    fn to_bytes(self: @EnclaveReport) -> Array<u8> {
        // convert the struct into raw bytes
        let mut raw_bytes = array![];
        // copy the fields into the raw bytes
        raw_bytes.append_span(self.cpu_svn.span());
        raw_bytes.append_span(self.misc_select.span());
        raw_bytes.append_span(self.reserved_1.span());
        raw_bytes.append_span(self.attributes.span());
        raw_bytes.append_span(self.mrenclave.span());
        raw_bytes.append_span(self.reserved_2.span());
        raw_bytes.append_span(self.mrsigner.span());
        raw_bytes.append_span(self.reserved_3.span());
        raw_bytes.append_span(self.isv_prod_id.to_le_bytes().span());
        raw_bytes.append_span(self.isv_svn.to_le_bytes().span());
        raw_bytes.append_span(self.reserved_4.span());
        raw_bytes.append_span(self.report_data.span());

        raw_bytes
    }
}

#[derive(Drop, Debug)]
pub struct TD10ReportBody {
    pub tee_tcb_svn: [u8; 16], // [16 bytes]
    // Describes the TCB of TDX. (Refer to above)
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub mrseam: Array<u8>, // [48 bytes]
    // Measurement of the TDX Module.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub mrsignerseam: Array<u8>, // [48 bytes]
    // Zero for Intel TDX Module
    pub seam_attributes: u64, // [8 bytes]
    // Must be zero for TDX 1.0
    pub td_attributes: u64, // [8 bytes]
    // TD Attributes (Refer to above)
    pub xfam: u64, // [8 bytes]
    // XFAM (eXtended Features Available Mask) is defined as a 64b bitmap, which has the same format
    // as XCR0 or IA32_XSS MSR.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub mrtd: Array<u8>, // [48 bytes]
    // (SHA384) Measurement of the initial contents of the TD.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub mrconfigid: Array<u8>, // [48 bytes]
    // Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS
    // configuration.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub mrowner: Array<u8>, // [48 bytes]
    // Software-defined ID for the TD's owner
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub mrownerconfig: Array<u8>, // [48 bytes]
    // Software-defined ID for owner-defined configuration of the TD,
    // e.g., specific to the workload rather than the runtime or OS.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub rtmr0: Array<u8>, // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub rtmr1: Array<u8>, // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub rtmr2: Array<u8>, // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    // CAIRO: Using Array<u8> instead of [u8; 48] because Cairo lacks built-in trait implementations
    // for arrays of size 48
    pub rtmr3: Array<u8>, // [48 bytes]
    // (SHA384) Root of Trust for Measurement (RTM) for the TD.
    // CAIRO: Using Array<u8> instead of [u8; 64] because Cairo lacks built-in trait implementations
    // for arrays of size 64
    pub report_data: Array<u8> // [64 bytes]
    // Additional report data.
// The TD is free to provide 64 bytes of custom data to the REPORT.
// This can be used to provide specific data from the TD or it can be used to hold a hash of a
// larger block of data which is provided with the quote.
// Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity
// is protected with a key rooted in an Intel CA.
}

#[generate_trait]
pub impl TD10ReportBodyImpl of TD10ReportBodyTrait {
    fn from_bytes(bytes: Span<u8>) -> TD10ReportBody {
        // tee_tcb_svn (16 bytes)
        let tee_tcb_svn = [
            *bytes[0], *bytes[1], *bytes[2], *bytes[3], *bytes[4], *bytes[5], *bytes[6], *bytes[7],
            *bytes[8], *bytes[9], *bytes[10], *bytes[11], *bytes[12], *bytes[13], *bytes[14],
            *bytes[15],
        ];

        // mrseam (48 bytes)
        let mrseam: Array<u8> = bytes.slice(16, 48).into();

        // mrsignerseam (48 bytes)
        let mrsignerseam: Array<u8> = bytes.slice(64, 48).into();

        // seam_attributes (8 bytes)
        let seam_attributes = U64FromLeBytes::from_le_bytes(
            [
                *bytes[112], *bytes[113], *bytes[114], *bytes[115], *bytes[116], *bytes[117],
                *bytes[118], *bytes[119],
            ],
        );

        // td_attributes (8 bytes)
        let td_attributes = U64FromLeBytes::from_le_bytes(
            [
                *bytes[120], *bytes[121], *bytes[122], *bytes[123], *bytes[124], *bytes[125],
                *bytes[126], *bytes[127],
            ],
        );

        // xfam (8 bytes)
        let xfam = U64FromLeBytes::from_le_bytes(
            [
                *bytes[128], *bytes[129], *bytes[130], *bytes[131], *bytes[132], *bytes[133],
                *bytes[134], *bytes[135],
            ],
        );

        // mrtd (48 bytes)
        let mrtd: Array<u8> = bytes.slice(136, 48).into();

        // mrconfigid (48 bytes)
        let mrconfigid: Array<u8> = bytes.slice(184, 48).into();

        // mrowner (48 bytes)
        let mrowner: Array<u8> = bytes.slice(232, 48).into();

        // mrownerconfig (48 bytes)
        let mrownerconfig: Array<u8> = bytes.slice(280, 48).into();

        // rtmr0 (48 bytes)
        let rtmr0: Array<u8> = bytes.slice(328, 48).into();

        // rtmr1 (48 bytes)
        let rtmr1: Array<u8> = bytes.slice(376, 48).into();

        // rtmr2 (48 bytes)
        let rtmr2: Array<u8> = bytes.slice(424, 48).into();

        // rtmr3 (48 bytes)
        let rtmr3: Array<u8> = bytes.slice(472, 48).into();

        // report_data (64 bytes)
        let report_data: Array<u8> = bytes.slice(520, 64).into();

        TD10ReportBody {
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seam_attributes,
            td_attributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            report_data,
        }
    }

    fn to_bytes(self: @TD10ReportBody) -> Array<u8> {
        // convert the struct into raw bytes
        let mut raw_bytes = array![];
        // copy the fields into the raw bytes
        raw_bytes.append_span(self.tee_tcb_svn.span());
        raw_bytes.append_span(self.mrseam.span());
        raw_bytes.append_span(self.mrsignerseam.span());
        raw_bytes.append_span(self.seam_attributes.to_le_bytes().span());
        raw_bytes.append_span(self.td_attributes.to_le_bytes().span());
        raw_bytes.append_span(self.xfam.to_le_bytes().span());
        raw_bytes.append_span(self.mrtd.span());
        raw_bytes.append_span(self.mrconfigid.span());
        raw_bytes.append_span(self.mrowner.span());
        raw_bytes.append_span(self.mrownerconfig.span());
        raw_bytes.append_span(self.rtmr0.span());
        raw_bytes.append_span(self.rtmr1.span());
        raw_bytes.append_span(self.rtmr2.span());
        raw_bytes.append_span(self.rtmr3.span());
        raw_bytes.append_span(self.report_data.span());

        raw_bytes
    }
}
