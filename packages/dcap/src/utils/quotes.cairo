use int_traits::U256FromBytesBe;
use x509_parser::certificate::{TbsCertificateTrait, X509Certificate};
use crate::constants::{ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID};
use crate::types::TcbStatus;
use crate::types::cert::{IntelSgxCrls, IntelSgxCrlsTrait, SgxExtensions};
use crate::types::collaterals::{IntelCollateral, IntelCollateralTrait};
use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::types::quotes::body::{EnclaveReport, EnclaveReportTrait, QuoteBody, TD10ReportBodyTrait};
use crate::types::quotes::{CertData, QuoteHeader, QuoteHeaderTrait};
use crate::types::tcbinfo::TcbInfo;
use crate::utils::cert::{
    extract_sgx_extension, get_x509_issuer_cn, get_x509_subject_cn, parse_x509_der_multi,
    verify_certchain_signature, verify_certificate, verify_crl,
};
use crate::utils::crypto::p256::compute_digest_ba;
use crate::utils::crypto::{
    verify_p256_signature_bytes_span, verify_p256_signature_bytes_span_no_pk_prefix,
};
use crate::utils::enclave_identity::{get_qe_tcbstatus, validate_enclave_identityv2};
use crate::utils::tcbinfo::validate_tcbinfov3;

pub mod version_4;

/// The string "Intel SGX PCK Platform CA".
const INTEL_SGX_PCK_PLATFORM_CA: [u8; 25] = [
    73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 80, 67, 75, 32, 80, 108, 97, 116, 102, 111, 114,
    109, 32, 67, 65,
];

/// The string "Intel SGX PCK Processor CA".
const INTEL_SGX_PCK_PROCESSOR_CA: [u8; 26] = [
    73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 80, 67, 75, 32, 80, 114, 111, 99, 101, 115, 115,
    111, 114, 32, 67, 65,
];


fn check_quote_header(quote_header: @QuoteHeader, quote_version: u16) -> bool {
    let quote_version_is_valid = *quote_header.version == quote_version;
    let att_key_type_is_supported = *quote_header.att_key_type == ECDSA_256_WITH_P256_CURVE;
    let qe_vendor_id_is_valid = *quote_header.qe_vendor_id == INTEL_QE_VENDOR_ID;

    quote_version_is_valid && att_key_type_is_supported && qe_vendor_id_is_valid
}

// verification steps that are required for both SGX and TDX quotes
// Checks:
// - valid qeidentity
// - valid tcbinfo
// - valid pck certificate chain
// - qe report content
// - ecdsa verification on qe report data and quote body data
// Returns:
// - QEIdentity TCB Status
// - SGX Extension
// - TCBInfo (v2 or v3)
fn common_verify_and_fetch_tcb(
    quote_header: @QuoteHeader,
    quote_body: @QuoteBody,
    ecdsa_attestation_signature: Span<u8>,
    ecdsa_attestation_pubkey: Span<u8>,
    qe_report: @EnclaveReport,
    qe_report_signature: Span<u8>,
    qe_auth_data: Span<u8>,
    qe_cert_data: @CertData,
    collaterals: @IntelCollateral,
    current_time: u64,
) -> (TcbStatus, SgxExtensions, TcbInfo) {
    let signing_cert = collaterals.get_sgx_tcb_signing();
    let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca();

    // verify that signing_verifying_key is not revoked and signed by the root cert
    let intel_crls = IntelSgxCrlsTrait::from_collaterals(collaterals);

    // ZL: If collaterals are checked by the caller, then these can be removed
    // check that CRLs are valid
    match @intel_crls.sgx_root_ca_crl {
        Option::Some(crl) => { assert!(verify_crl(crl, @intel_sgx_root_cert, current_time)); },
        Option::None => { panic!("No SGX Root CA CRL found"); },
    }

    let signing_cert_revoked = intel_crls.is_cert_revoked(@signing_cert);
    assert!(!signing_cert_revoked, "TCB Signing Cert revoked");
    assert!(
        verify_certificate(@signing_cert, @intel_sgx_root_cert, current_time),
        "TCB Signing Cert is not signed by Intel SGX Root CA",
    );

    // validate QEIdentity
    let qeidentityv2 = collaterals.get_qeidentity();
    assert!(validate_enclave_identityv2(qeidentityv2, @signing_cert, current_time));

    // verify QEReport then get TCB Status
    assert!(
        verify_qe_report_data(
            @qe_report.report_data.span(), @ecdsa_attestation_pubkey, @qe_auth_data,
        ),
        "QE Report Data is incorrect",
    );
    assert!(
        validate_qe_report(qe_report, qeidentityv2),
        "QE Report values do not match with the provided QEIdentity",
    );
    let qe_tcb_status = get_qe_tcbstatus(qe_report, qeidentityv2);
    assert!(qe_tcb_status != TcbStatus::TcbRevoked, "QEIdentity TCB Revoked");

    // get the certchain embedded in the ecda quote signature data
    // this can be one of 5 types
    // we only handle type 5 for now...
    // TODO: Add support for all other types
    assert!(qe_cert_data.cert_data_type == @5, "QE Cert Type must be 5");

    // CAIRO: In Cairo PEM parsing is offloaded into an offchain CLI that pre-processes the
    // `CertData` to internally convert base64 content into continuous DER-encoded certs.
    let certchain = parse_x509_der_multi(@qe_cert_data.cert_data.span());
    // checks that the certificates used in the certchain are not revoked
    for cert in @certchain {
        assert!(!intel_crls.is_cert_revoked(cert));
    }

    // get the pck certificate, and check whether issuer common name is valid
    let pck_cert = certchain[0];
    let pck_cert_issuer = certchain[1];
    assert!(
        check_pck_issuer_and_crl(pck_cert, pck_cert_issuer, @intel_crls, current_time),
        "Invalid PCK Issuer or CRL",
    );

    // verify that the cert chain signatures are valid
    assert!(
        verify_certchain_signature(certchain.span(), @intel_sgx_root_cert, current_time),
        "Invalid PCK Chain",
    );

    // verify the signature for qe report data
    let qe_report_bytes = qe_report.to_bytes();

    let qe_report_public_key = pck_cert.tbs_certificate.public_key().subject_public_key.data;
    assert!(
        verify_p256_signature_bytes_span(
            @qe_report_bytes.span(), @qe_report_signature, qe_report_public_key,
        ),
        "Invalid qe signature",
    );

    // get the SGX extension
    let sgx_extensions = extract_sgx_extension(pck_cert);

    // verify the signature for attestation body
    let mut data = array![];
    data.append_span(quote_header.to_bytes().span());
    match quote_body {
        QuoteBody::SGXQuoteBody(_) => {
            // CAIRO: TODO panic for SGX quotes - only TDX is implemented
            panic!("TODO: common_verify_and_fetch_tcb - SGX quote not implemented");
        },
        QuoteBody::TD10QuoteBody(body) => { data.append_span(body.to_bytes().span()); },
    }

    // CAIRO: Removed public key prefixing as we have a variant that takes non-SEC1 format.
    assert!(
        verify_p256_signature_bytes_span_no_pk_prefix(
            @data.span(), @ecdsa_attestation_signature, @ecdsa_attestation_pubkey,
        ),
        "Invalid attestation signature",
    );

    // validate tcbinfo v2 or v3, depending on the quote version
    let tcb_info = if quote_header.version >= @4 {
        let tcb_info_v3 = collaterals.get_tcbinfov3();
        assert!(validate_tcbinfov3(tcb_info_v3, @signing_cert, current_time), "Invalid TCBInfoV3");
        TcbInfo::V3(tcb_info_v3)
    } else {
        panic!("TODO: common_verify_and_fetch_tcb - non-v4 quotes not implemented")
    };

    (qe_tcb_status, sgx_extensions, tcb_info)
}

fn check_pck_issuer_and_crl(
    pck_cert: @X509Certificate,
    pck_issuer_cert: @X509Certificate,
    intel_crls: @IntelSgxCrls,
    current_time: u64,
) -> bool {
    // we'll check what kind of cert is it, and validate the appropriate CRL
    let pck_cert_subject_cn = get_x509_issuer_cn(pck_cert);
    let pck_cert_issuer_cn = get_x509_subject_cn(pck_issuer_cert);

    assert!(
        pck_cert_issuer_cn == pck_cert_subject_cn,
        "PCK Issuer CN does not match with PCK Intermediate Subject CN",
    );

    if pck_cert_issuer_cn == @INTEL_SGX_PCK_PLATFORM_CA.span() {
        match @intel_crls.sgx_pck_platform_crl {
            Option::Some(crl) => verify_crl(*crl, pck_issuer_cert, current_time),
            Option::None => panic!("No SGX PCK Platform CRL found"),
        }
    } else if pck_cert_issuer_cn == @INTEL_SGX_PCK_PROCESSOR_CA.span() {
        match @intel_crls.sgx_pck_processor_crl {
            Option::Some(crl) => verify_crl(*crl, pck_issuer_cert, current_time),
            Option::None => panic!("No SGX PCK Processor CRL found"),
        }
    } else {
        panic!("Unknown PCK Cert Subject CN: {:?}", pck_cert_subject_cn)
    }
}

fn validate_qe_report(enclave_report: @EnclaveReport, qeidentityv2: @EnclaveIdentityV2) -> bool {
    // make sure that the enclave_identityv2 is a qeidentityv2
    // check that id is "QE", "TD_QE" or "QVE" and version is 2
    if !((qeidentityv2.enclave_identity.id == @"QE"
        || qeidentityv2.enclave_identity.id == @"TD_QE"
        || qeidentityv2.enclave_identity.id == @"QVE")
        && qeidentityv2.enclave_identity.version == @2) {
        return false;
    }

    // CAIRO: Rewrote `mrsigner_ok` to not require hex parsing.
    if enclave_report.mrsigner.span() != *qeidentityv2.enclave_identity.mrsigner {
        return false;
    }

    // CAIRO: Rewrote `isvprodid_ok` to not require hex parsing.
    if enclave_report.isv_prod_id != qeidentityv2.enclave_identity.isvprodid {
        return false;
    }

    // CAIRO: Rewrote `enclave_attributes_ok` to use iterators.
    let mut attributes_mask_iter = qeidentityv2.enclave_identity.attributes_mask.clone();
    let mut attributes_iter = qeidentityv2.enclave_identity.attributes.clone();
    let mut enclave_report_attributes_iter = enclave_report.attributes.span();
    if !eq_masked(
        ref attributes_iter, ref enclave_report_attributes_iter, ref attributes_mask_iter,
    ) {
        return false;
    }

    // CAIRO: Rewrote `enclave_miscselect_ok` to use iterators.
    let mut miscselect_mask_iter = qeidentityv2.enclave_identity.miscselect_mask.clone();
    let mut miscselect_iter = qeidentityv2.enclave_identity.miscselect.clone();
    let mut enclave_report_misc_select_iter = enclave_report.misc_select.span();
    eq_masked(ref miscselect_iter, ref enclave_report_misc_select_iter, ref miscselect_mask_iter)
}

fn verify_qe_report_data(
    report_data: @Span<u8>, ecdsa_attestation_key: @Span<u8>, qe_auth_data: @Span<u8>,
) -> bool {
    let mut concat = Default::<ByteArray>::default();
    for byte in ecdsa_attestation_key {
        concat.append_byte(*byte);
    }
    for byte in qe_auth_data {
        concat.append_byte(*byte);
    }

    // CAIRO: Rewrote comparison logic to avoid direct array equality check.
    let digest = compute_digest_ba(@concat);
    if report_data.len() != 64 {
        return false;
    }
    U256FromBytesBe::from_be_byte_span(@report_data.slice(0, 32)) == digest
        && U256FromBytesBe::from_be_byte_span(@report_data.slice(32, 32)) == 0
}

// CAIRO: Helper function for comparing masked bytes.
fn eq_masked(ref left: Span<u8>, ref right: Span<u8>, ref mask: Span<u8>) -> bool {
    loop {
        let mask_byte = match mask.pop_front() {
            Some(byte) => *byte,
            None => { break left.len() == 0 && right.len() == 0; },
        };
        let left_byte = match left.pop_front() {
            Some(byte) => *byte,
            None => { break false; },
        };
        let right_byte = match right.pop_front() {
            Some(byte) => *byte,
            None => { break false; },
        };

        if left_byte & mask_byte != right_byte & mask_byte {
            break false;
        }
    }
}

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
pub fn converge_tcb_status_with_qe_tcb(
    tcb_status: TcbStatus, qe_tcb_status: TcbStatus,
) -> TcbStatus {
    match qe_tcb_status {
        TcbStatus::TcbOutOfDate => {
            if tcb_status == TcbStatus::OK || tcb_status == TcbStatus::TcbSwHardeningNeeded {
                TcbStatus::TcbOutOfDate
            } else if tcb_status == TcbStatus::TcbConfigurationNeeded
                || tcb_status == TcbStatus::TcbConfigurationAndSwHardeningNeeded {
                TcbStatus::TcbOutOfDateConfigurationNeeded
            } else {
                tcb_status
            }
        },
        _ => { tcb_status },
    }
}
