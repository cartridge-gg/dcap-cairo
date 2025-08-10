use time::{DateTrait, Month, OffsetDateTimeTrait, TimeTrait};
use crate::types::enclave_identity::{
    EnclaveIdentityV2, EnclaveIdentityV2Inner, EnclaveIdentityV2TcbLevel,
    EnclaveIdentityV2TcbLevelItem,
};

pub fn data() -> EnclaveIdentityV2 {
    // 2025-02-13T03:39:00Z
    let issue_date = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2025, Month::February, 13).unwrap(),
        TimeTrait::from_hms_milli(3, 39, 0, 0).unwrap(),
    );

    // 2025-03-15T03:39:00Z
    let next_update = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2025, Month::March, 15).unwrap(),
        TimeTrait::from_hms_milli(3, 39, 0, 0).unwrap(),
    );

    // 2024-03-13T00:00:00Z
    let tcb_date = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2024, Month::March, 13).unwrap(),
        TimeTrait::from_hms_milli(0, 0, 0, 0).unwrap(),
    );

    EnclaveIdentityV2 {
        enclave_identity: EnclaveIdentityV2Inner {
            id: "TD_QE",
            version: 2,
            issue_date,
            next_update,
            tcb_evaluation_data_number: 17,
            miscselect: array![0x00, 0x00, 0x00, 0x00].span(),
            miscselect_mask: array![0xFF, 0xFF, 0xFF, 0xFF].span(),
            attributes: array![
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
                .span(),
            attributes_mask: array![
                0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
                .span(),
            mrsigner: array![
                0xDC, 0x9E, 0x2A, 0x7C, 0x6F, 0x94, 0x8F, 0x17, 0x47, 0x4E, 0x34, 0xA7, 0xFC, 0x43,
                0xED, 0x03, 0x0F, 0x7C, 0x15, 0x63, 0xF1, 0xBA, 0xBD, 0xDF, 0x63, 0x40, 0xC8, 0x2E,
                0x0E, 0x54, 0xA8, 0xC5,
            ]
                .span(),
            isvprodid: 2,
            tcb_levels: array![
                EnclaveIdentityV2TcbLevelItem {
                    tcb: EnclaveIdentityV2TcbLevel { isvsvn: 4 },
                    tcb_date,
                    tcb_status: "UpToDate",
                    advisory_ids: Option::None,
                },
            ]
                .span(),
        },
        signature: array![
            0x80, 0x6c, 0x26, 0x41, 0x15, 0xa8, 0x83, 0x17, 0x35, 0x94, 0x03, 0x5b, 0x66, 0x73,
            0x58, 0x44, 0x9d, 0x22, 0x78, 0xe9, 0x5e, 0x86, 0x5f, 0x97, 0xe5, 0x1f, 0x39, 0xb6,
            0x3c, 0xf1, 0xab, 0x41, 0xfb, 0x05, 0x28, 0x59, 0xae, 0x37, 0xd1, 0x69, 0xef, 0x4e,
            0x4f, 0x9d, 0x09, 0xdd, 0xbf, 0x60, 0xf2, 0x6c, 0xeb, 0xb6, 0x01, 0x2e, 0xed, 0x68,
            0x9e, 0xea, 0xe2, 0xc5, 0x23, 0x0d, 0x7a, 0x22,
        ]
            .span(),
    }
}
