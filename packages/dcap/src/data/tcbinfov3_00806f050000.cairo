use time::{DateTrait, Month, OffsetDateTimeTrait, TimeTrait};
use crate::types::tcbinfo::{
    TcbComponent, TcbInfoV3, TcbInfoV3Inner, TcbInfoV3TcbLevel, TcbInfoV3TcbLevelItem, TdxModule,
    TdxModuleIdentities, TdxModuleIdentitiesTcbLevel, TdxModuleIdentitiesTcbLevelItem,
};

pub fn data() -> TcbInfoV3 {
    // 2025-02-13T03:50:41Z
    let issue_date = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2025, Month::February, 13).unwrap(),
        TimeTrait::from_hms_milli(3, 50, 41, 0).unwrap(),
    );

    // 2025-03-15T03:50:41Z
    let next_update = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2025, Month::March, 15).unwrap(),
        TimeTrait::from_hms_milli(3, 50, 41, 0).unwrap(),
    );

    // 2024-03-13T00:00:00Z
    let tcb_date_2024_03_13 = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2024, Month::March, 13).unwrap(),
        TimeTrait::from_hms_milli(0, 0, 0, 0).unwrap(),
    );

    // 2023-08-09T00:00:00Z
    let tcb_date_2023_08_09 = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2023, Month::August, 9).unwrap(),
        TimeTrait::from_hms_milli(0, 0, 0, 0).unwrap(),
    );

    // 2023-02-15T00:00:00Z
    let tcb_date_2023_02_15 = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2023, Month::February, 15).unwrap(),
        TimeTrait::from_hms_milli(0, 0, 0, 0).unwrap(),
    );

    // 2018-01-04T00:00:00Z
    let tcb_date_2018_01_04 = OffsetDateTimeTrait::new_utc(
        DateTrait::from_calendar_date(2018, Month::January, 4).unwrap(),
        TimeTrait::from_hms_milli(0, 0, 0, 0).unwrap(),
    );

    TcbInfoV3 {
        tcb_info: TcbInfoV3Inner {
            id: "TDX",
            version: 3,
            issue_date,
            next_update,
            fmspc: [0x00, 0x80, 0x6f, 0x05, 0x00, 0x00].span(),
            pce_id: [0x00, 0x00].span(),
            tcb_type: 0,
            tcb_evaluation_data_number: 17,
            tdx_module: Option::Some(
                TdxModule {
                    mrsigner: array![
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ]
                        .span(),
                    attributes: array![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].span(),
                    attributes_mask: array![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].span(),
                },
            ),
            tdx_module_identities: Option::Some(
                array![
                    TdxModuleIdentities {
                        id: "TDX_03",
                        mrsigner: array![
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ]
                            .span(),
                        attributes: array![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].span(),
                        attributes_mask: array![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                            .span(),
                        tcb_levels: array![
                            TdxModuleIdentitiesTcbLevelItem {
                                tcb: TdxModuleIdentitiesTcbLevel { isvsvn: 3 },
                                tcb_date: tcb_date_2024_03_13,
                                tcb_status: "UpToDate",
                                advisory_ids: Option::None,
                            },
                        ],
                    },
                    TdxModuleIdentities {
                        id: "TDX_01",
                        mrsigner: array![
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ]
                            .span(),
                        attributes: array![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].span(),
                        attributes_mask: array![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                            .span(),
                        tcb_levels: array![
                            TdxModuleIdentitiesTcbLevelItem {
                                tcb: TdxModuleIdentitiesTcbLevel { isvsvn: 4 },
                                tcb_date: tcb_date_2024_03_13,
                                tcb_status: "UpToDate",
                                advisory_ids: Option::None,
                            },
                            TdxModuleIdentitiesTcbLevelItem {
                                tcb: TdxModuleIdentitiesTcbLevel { isvsvn: 2 },
                                tcb_date: tcb_date_2023_08_09,
                                tcb_status: "OutOfDate",
                                advisory_ids: Option::None,
                            },
                        ],
                    },
                ],
            ),
            tcb_levels: array![
                TcbInfoV3TcbLevelItem {
                    tcb: TcbInfoV3TcbLevel {
                        sgxtcbcomponents: array![
                            TcbComponent {
                                svn: 7,
                                category: Option::Some("BIOS"),
                                type_: Option::Some("Early Microcode Update"),
                            },
                            TcbComponent {
                                svn: 7,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SGX Late Microcode Update"),
                            },
                            TcbComponent {
                                svn: 2,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("TXT SINIT"),
                            },
                            TcbComponent {
                                svn: 2, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 3, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 1, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent {
                                svn: 3,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SEAMLDR ACM"),
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                        ],
                        pcesvn: 11,
                        tdxtcbcomponents: Option::Some(
                            array![
                                TcbComponent {
                                    svn: 5,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 0,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 7,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Late Microcode Update"),
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                            ],
                        ),
                    },
                    tcb_date: tcb_date_2024_03_13,
                    tcb_status: "UpToDate",
                    advisory_ids: Option::None,
                },
                TcbInfoV3TcbLevelItem {
                    tcb: TcbInfoV3TcbLevel {
                        sgxtcbcomponents: array![
                            TcbComponent {
                                svn: 6,
                                category: Option::Some("BIOS"),
                                type_: Option::Some("Early Microcode Update"),
                            },
                            TcbComponent {
                                svn: 6,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SGX Late Microcode Update"),
                            },
                            TcbComponent {
                                svn: 2,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("TXT SINIT"),
                            },
                            TcbComponent {
                                svn: 2, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 3, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 1, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent {
                                svn: 3,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SEAMLDR ACM"),
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                        ],
                        pcesvn: 11,
                        tdxtcbcomponents: Option::Some(
                            array![
                                TcbComponent {
                                    svn: 3,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 0,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 6,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Late Microcode Update"),
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                            ],
                        ),
                    },
                    tcb_date: tcb_date_2023_08_09,
                    tcb_status: "OutOfDate",
                    advisory_ids: Option::Some(
                        array!["INTEL-SA-00960", "INTEL-SA-00982", "INTEL-SA-00986"].span(),
                    ),
                },
                TcbInfoV3TcbLevelItem {
                    tcb: TcbInfoV3TcbLevel {
                        sgxtcbcomponents: array![
                            TcbComponent {
                                svn: 5,
                                category: Option::Some("BIOS"),
                                type_: Option::Some("Early Microcode Update"),
                            },
                            TcbComponent {
                                svn: 5,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SGX Late Microcode Update"),
                            },
                            TcbComponent {
                                svn: 2,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("TXT SINIT"),
                            },
                            TcbComponent {
                                svn: 2, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 3, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 1, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent {
                                svn: 3,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SEAMLDR ACM"),
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                        ],
                        pcesvn: 11,
                        tdxtcbcomponents: Option::Some(
                            array![
                                TcbComponent {
                                    svn: 3,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 0,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 5,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Late Microcode Update"),
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                            ],
                        ),
                    },
                    tcb_date: tcb_date_2023_02_15,
                    tcb_status: "OutOfDate",
                    advisory_ids: Option::Some(
                        array![
                            "INTEL-SA-00837", "INTEL-SA-00960", "INTEL-SA-00982", "INTEL-SA-00986",
                        ]
                            .span(),
                    ),
                },
                TcbInfoV3TcbLevelItem {
                    tcb: TcbInfoV3TcbLevel {
                        sgxtcbcomponents: array![
                            TcbComponent {
                                svn: 5,
                                category: Option::Some("BIOS"),
                                type_: Option::Some("Early Microcode Update"),
                            },
                            TcbComponent {
                                svn: 5,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SGX Late Microcode Update"),
                            },
                            TcbComponent {
                                svn: 2,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("TXT SINIT"),
                            },
                            TcbComponent {
                                svn: 2, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 3, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent {
                                svn: 1, category: Option::Some("BIOS"), type_: Option::None,
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent {
                                svn: 3,
                                category: Option::Some("OS/VMM"),
                                type_: Option::Some("SEAMLDR ACM"),
                            },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                            TcbComponent { svn: 0, category: Option::None, type_: Option::None },
                        ],
                        pcesvn: 5,
                        tdxtcbcomponents: Option::Some(
                            array![
                                TcbComponent {
                                    svn: 3,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 0,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Module"),
                                },
                                TcbComponent {
                                    svn: 5,
                                    category: Option::Some("OS/VMM"),
                                    type_: Option::Some("TDX Late Microcode Update"),
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                                TcbComponent {
                                    svn: 0, category: Option::None, type_: Option::None,
                                },
                            ],
                        ),
                    },
                    tcb_date: tcb_date_2018_01_04,
                    tcb_status: "OutOfDate",
                    advisory_ids: Option::Some(
                        array![
                            "INTEL-SA-00106", "INTEL-SA-00115", "INTEL-SA-00135", "INTEL-SA-00203",
                            "INTEL-SA-00220", "INTEL-SA-00233", "INTEL-SA-00270", "INTEL-SA-00293",
                            "INTEL-SA-00320", "INTEL-SA-00329", "INTEL-SA-00381", "INTEL-SA-00389",
                            "INTEL-SA-00477", "INTEL-SA-00837", "INTEL-SA-00960", "INTEL-SA-00982",
                            "INTEL-SA-00986",
                        ]
                            .span(),
                    ),
                },
            ],
        },
        signature: array![
            0xef, 0xd7, 0x9a, 0x5c, 0x34, 0x45, 0xd3, 0xaf, 0x81, 0x06, 0x8f, 0xc0, 0xbc, 0x6a,
            0xc0, 0x13, 0xa8, 0x7c, 0x6a, 0xea, 0x91, 0x08, 0x8c, 0x43, 0x73, 0xea, 0xc8, 0xde,
            0x0b, 0x9a, 0x99, 0xee, 0x27, 0xde, 0x6e, 0xaf, 0x3e, 0x28, 0xa6, 0xad, 0x77, 0xf1,
            0x19, 0x9f, 0xb2, 0x83, 0xed, 0xbb, 0x99, 0xed, 0x89, 0x40, 0xb4, 0xda, 0xc5, 0x68,
            0xd7, 0x81, 0x02, 0xe5, 0x90, 0xa7, 0xdc, 0x71,
        ]
            .span(),
    }
}
