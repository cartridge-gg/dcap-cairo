use time::OffsetDateTimeTrait;
use x509_parser::certificate::{TbsCertificateTrait, X509Certificate};
use crate::json::JsonSerialize;
use crate::types::TcbStatus;
use crate::types::enclave_identity::{EnclaveIdentityV2, EnclaveIdentityV2Inner};
use crate::types::quotes::body::EnclaveReport;
use crate::utils::crypto::verify_p256_signature_bytes;

pub fn validate_enclave_identityv2(
    enclave_identityv2: @EnclaveIdentityV2, sgx_signing_pubkey: @X509Certificate, current_time: u64,
) -> bool {
    // get tcb_info_root time
    let issue_date = enclave_identityv2.enclave_identity.issue_date;
    let next_update_date = enclave_identityv2.enclave_identity.next_update;

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds: u64 = issue_date.unix_timestamp().try_into().unwrap();
    let next_update_seconds: u64 = next_update_date.unix_timestamp().try_into().unwrap();

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        return false;
    }

    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let enclave_identityv2_signature_bytes: @Span<u8> = enclave_identityv2.signature;

    // verify that the enclave_identity_root is signed by the root cert
    let mut enclave_identityv2_signature_data: ByteArray = "";
    JsonSerialize::<
        EnclaveIdentityV2Inner,
    >::serialize(enclave_identityv2.enclave_identity, ref enclave_identityv2_signature_data);
    verify_p256_signature_bytes(
        @enclave_identityv2_signature_data,
        enclave_identityv2_signature_bytes,
        sgx_signing_pubkey.tbs_certificate.public_key().subject_public_key.data,
    )
}

pub fn get_qe_tcbstatus(
    enclave_report: @EnclaveReport, qeidentityv2: @EnclaveIdentityV2,
) -> TcbStatus {
    for tcb_level in qeidentityv2.enclave_identity.tcb_levels {
        if tcb_level.tcb.isvsvn <= enclave_report.isv_svn {
            let tcb_status = if tcb_level.tcb_status == @"UpToDate" {
                TcbStatus::OK
            } else if tcb_level.tcb_status == @"SWHardeningNeeded" {
                TcbStatus::TcbSwHardeningNeeded
            } else if tcb_level.tcb_status == @"ConfigurationAndSWHardeningNeeded" {
                TcbStatus::TcbConfigurationAndSwHardeningNeeded
            } else if tcb_level.tcb_status == @"ConfigurationNeeded" {
                TcbStatus::TcbConfigurationNeeded
            } else if tcb_level.tcb_status == @"OutOfDate" {
                TcbStatus::TcbOutOfDate
            } else if tcb_level.tcb_status == @"OutOfDateConfigurationNeeded" {
                TcbStatus::TcbOutOfDateConfigurationNeeded
            } else if tcb_level.tcb_status == @"Revoked" {
                TcbStatus::TcbRevoked
            } else {
                TcbStatus::TcbUnrecognized
            };
            return tcb_status;
        }
    }

    TcbStatus::TcbUnrecognized
}
