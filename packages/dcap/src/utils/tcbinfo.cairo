use time::OffsetDateTimeTrait;
use x509_parser::certificate::{TbsCertificateTrait, X509Certificate};
use crate::json::JsonSerialize;
use crate::types::tcbinfo::{TcbInfoV3, TcbInfoV3Inner};
use crate::utils::crypto::verify_p256_signature_bytes;

pub fn validate_tcbinfov3(
    tcbinfov3: @TcbInfoV3, sgx_signing_cert: @X509Certificate, current_time: u64,
) -> bool {
    // get tcb_info_root time
    let issue_date = tcbinfov3.tcb_info.issue_date;
    let next_update_date = tcbinfov3.tcb_info.next_update;

    // convert the issue_date and next_update_date to seconds since epoch
    let issue_date_seconds: u64 = issue_date.unix_timestamp().try_into().unwrap();
    let next_update_seconds: u64 = next_update_date.unix_timestamp().try_into().unwrap();

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        panic!();
    }

    // signature is a hex string, we'll convert it to bytes
    // ZL: we'll assume that the signature is a P256 ECDSA signature
    let tcbinfov3_signature_bytes = tcbinfov3.signature;

    // verify that the tcb_info_root is signed by the root cert
    let mut tcbinfov3_signature_data: ByteArray = "";
    JsonSerialize::<TcbInfoV3Inner>::serialize(tcbinfov3.tcb_info, ref tcbinfov3_signature_data);
    verify_p256_signature_bytes(
        @tcbinfov3_signature_data,
        tcbinfov3_signature_bytes,
        sgx_signing_cert.tbs_certificate.public_key().subject_public_key.data,
    )
}
