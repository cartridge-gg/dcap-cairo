use int_traits::U64FromBeBytes;
use crate::json::append_hex_byte_lowercase;
use crate::types::tcbinfo::TcbInfoV3;
use crate::types::{TcbStatus, TcbStatusTrait};

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
pub fn get_tdx_module_identity_and_tcb(
    tee_tcb_svn: @[u8; 16], tcb_info_v3: @TcbInfoV3,
) -> (TcbStatus, Span<u8>, u64) {
    let tdx_module = match tcb_info_v3.tcb_info.tdx_module {
        Option::Some(tdx_module_obj) => tdx_module_obj,
        Option::None => { panic!("TDX module not found") },
    };

    let mut tee_tcb_svn_span = tee_tcb_svn.span();
    let tdx_module_isv_svn = *tee_tcb_svn_span.pop_front().unwrap();
    let tdx_module_version = *tee_tcb_svn_span.pop_front().unwrap();

    if tdx_module_version == 0 {
        let mrsigner = tdx_module.mrsigner;
        assert!(mrsigner.len() == 48, "Invalid mrsigner length");

        return (TcbStatus::OK, *mrsigner, from_str_to_u64(tdx_module.attributes));
    }

    let mut tdx_module_identity_id: ByteArray = "TDX_";
    append_hex_byte_lowercase(tdx_module_version, ref tdx_module_identity_id);

    match tcb_info_v3.tcb_info.tdx_module_identities {
        Option::Some(tdx_module_identities) => {
            for tdx_module_identity in tdx_module_identities {
                if tdx_module_identity.id == @tdx_module_identity_id {
                    for tcb_level in tdx_module_identity.tcb_levels {
                        if tdx_module_isv_svn >= *tcb_level.tcb.isvsvn {
                            let mrsigner = tdx_module_identity.mrsigner;
                            assert!(mrsigner.len() == 48, "Invalid mrsigner length");
                            let attributes = tdx_module_identity.attributes;
                            let tcb_status = TcbStatusTrait::from_str(tcb_level.tcb_status);
                            return (tcb_status, *mrsigner, from_str_to_u64(attributes));
                        }
                    }
                }
            }
        },
        Option::None => { panic!("TDX module identities not found") },
    }

    panic!(
        "TDX Module could not match to any TCB Level for TSX Module ISVSN: {}", tdx_module_isv_svn,
    )
}

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L137
pub fn converge_tcb_status_with_tdx_module_tcb(
    tcb_status: TcbStatus, tdx_module_tcb_status: TcbStatus,
) -> TcbStatus {
    match tdx_module_tcb_status {
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

fn from_str_to_u64(bytes: @Span<u8>) -> u64 {
    assert!(bytes.len() == 8, "invalid u64 bytes length");

    U64FromBeBytes::from_be_bytes(
        [*bytes[0], *bytes[1], *bytes[2], *bytes[3], *bytes[4], *bytes[5], *bytes[6], *bytes[7]],
    )
}
