use crate::constants::SGX_TEE_TYPE;
use crate::types::collaterals::IntelCollateral;
use crate::types::quotes::body::QuoteBody;
use crate::types::quotes::version_4::QuoteV4;
use crate::types::quotes::{CertDataTrait, CertDataType};
use crate::types::tcbinfo::TcbInfo;
use crate::types::{TcbStatus, VerifiedOutput};
use crate::utils::cert::get_sgx_tdx_fmspc_tcbstatus_v3;
use crate::utils::tdx_module::{
    converge_tcb_status_with_tdx_module_tcb, get_tdx_module_identity_and_tcb,
};
use super::{check_quote_header, common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb};

pub fn verify_quote_dcapv4(
    quote: @QuoteV4, collaterals: @IntelCollateral, current_time: u64,
) -> VerifiedOutput {
    assert!(check_quote_header(quote.header, 4), "invalid quote header");

    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = quote.signature.qe_cert_data;

    let qe_report_cert_data = match qe_cert_data_v4.get_cert_data() {
        CertDataType::QeReportCertData(qe_report_cert_data) => qe_report_cert_data,
        _ => { panic!("Unsupported CertDataType in QuoteSignatureDataV4") },
    };

    let (qe_tcb_status, sgx_extensions, tcb_info) = common_verify_and_fetch_tcb(
        quote.header,
        quote.quote_body,
        quote.signature.quote_signature.span(),
        quote.signature.ecdsa_attestation_key.span(),
        @qe_report_cert_data.qe_report,
        qe_report_cert_data.qe_report_signature.span(),
        qe_report_cert_data.qe_auth_data.data.span(),
        @qe_report_cert_data.qe_cert_data,
        collaterals,
        current_time,
    );

    let tcb_info_v3 = match tcb_info {
        TcbInfo::V3(tcb) => tcb,
        _ => panic!("TcbInfo must be V3!"),
    };

    let (quote_tdx_body, tee_tcb_svn) = match quote.quote_body {
        QuoteBody::TD10QuoteBody(body) => { (Some(body), body.tee_tcb_svn) },
        QuoteBody::SGXQuoteBody(_) => {
            // SGX does not produce tee_tcb_svns
            (None, @[0; 16])
        },
    };

    let tee_type = quote.header.tee_type;
    let (sgx_tcb_status, tdx_tcb_status, advisory_ids) = get_sgx_tdx_fmspc_tcbstatus_v3(
        *tee_type, @sgx_extensions, tee_tcb_svn, tcb_info_v3,
    );

    assert!(
        sgx_tcb_status != TcbStatus::TcbRevoked || tdx_tcb_status != TcbStatus::TcbRevoked,
        "FMSPC TCB Revoked",
    );

    let mut tcb_status: TcbStatus = if *quote.header.tee_type == SGX_TEE_TYPE {
        sgx_tcb_status
    } else {
        // Fetch TDXModule TCB and TDXModule Identity
        let (tdx_module_tcb_status, tdx_module_mrsigner, tdx_module_attributes) =
            get_tdx_module_identity_and_tcb(
            tee_tcb_svn, tcb_info_v3,
        );

        assert!(tdx_module_tcb_status != TcbStatus::TcbRevoked, "TDX Module TCB Revoked");

        // check TDX module
        let (tdx_report_mrsigner, tdx_report_attributes) = match quote_tdx_body {
            Option::Some(tdx_body) => { (tdx_body.mrsignerseam.span(), *tdx_body.seam_attributes) },
            Option::None => { panic!("Expected TDX body for TDX quote") },
        };

        let mr_signer_matched = tdx_module_mrsigner == tdx_report_mrsigner;
        let attributes_matched = tdx_module_attributes == tdx_report_attributes;
        assert!(mr_signer_matched && attributes_matched, "TDX module values mismatch");

        converge_tcb_status_with_tdx_module_tcb(tdx_tcb_status, tdx_module_tcb_status)
    };

    tcb_status = converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status);

    VerifiedOutput {
        quote_version: *quote.header.version,
        tee_type: *quote.header.tee_type,
        tcb_status: tcb_status,
        fmspc: sgx_extensions.fmspc,
        quote_body: quote.quote_body,
        advisory_ids: advisory_ids,
    }
}
