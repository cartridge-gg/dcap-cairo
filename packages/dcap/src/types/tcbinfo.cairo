use time::OffsetDateTime;

#[derive(Drop, Debug)]
pub enum TcbInfo {
    V2: @TcbInfoV2,
    V3: @TcbInfoV3,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV2 {
    pub tcb_info: TcbInfoV2Inner,
    pub signature: ByteArray,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV2Inner {
    pub version: u32,
    pub issue_date: ByteArray,
    pub next_update: ByteArray,
    pub fmspc: ByteArray,
    pub pce_id: ByteArray,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Array<TcbInfoV2TcbLevelItem>,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV2TcbLevelItem {
    pub tcb: TcbInfoV2TcbLevel,
    pub tcb_date: ByteArray,
    pub tcb_status: ByteArray,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV2TcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV3 {
    pub tcb_info: TcbInfoV3Inner,
    pub signature: Span<u8>,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV3Inner {
    pub id: ByteArray,
    pub version: u32,
    pub issue_date: OffsetDateTime,
    pub next_update: OffsetDateTime,
    pub fmspc: Span<u8>,
    pub pce_id: Span<u8>,
    pub tcb_type: u8,
    pub tcb_evaluation_data_number: u32,
    pub tdx_module: Option<TdxModule>,
    pub tdx_module_identities: Option<Array<TdxModuleIdentities>>,
    pub tcb_levels: Array<TcbInfoV3TcbLevelItem>,
}

#[derive(Drop, Debug)]
pub struct TdxModule {
    pub mrsigner: Span<
        u8,
    >, // Base 16-encoded string representation of the measurement of a TDX SEAM module's signer.
    pub attributes: Span<
        u8,
    >, // Hex-encoded byte array (8 bytes) representing attributes "golden" value.
    pub attributes_mask: Span<
        u8,
    > // Hex-encoded byte array (8 bytes) representing mask to be applied to TDX SEAM module's
    // attributes value retrieved from the platform
}

#[derive(Drop, Debug)]
pub struct TdxModuleIdentities {
    pub id: ByteArray, // Identifier of TDX Module
    pub mrsigner: Span<
        u8,
    >, // Base 16-encoded string representation of the measurement of a TDX SEAM module's signer.
    pub attributes: Span<
        u8,
    >, // Base 16-encoded string representation of the byte array (8 bytes) representing attributes "golden" value.
    pub attributes_mask: Span<
        u8,
    >, // Base 16-encoded string representation of the byte array (8 bytes) representing mask to be applied to TDX SEAM module's
    // attributes value retrieved from the platform
    pub tcb_levels: Array<TdxModuleIdentitiesTcbLevelItem>,
}

#[derive(Drop, Debug)]
pub struct TdxModuleIdentitiesTcbLevelItem {
    pub tcb: TdxModuleIdentitiesTcbLevel,
    pub tcb_date: OffsetDateTime,
    pub tcb_status: ByteArray,
    pub advisory_ids: Option<Span<ByteArray>>,
}

#[derive(Drop, Debug)]
pub struct TdxModuleIdentitiesTcbLevel {
    pub isvsvn: u8 // TDX SEAM module's ISV SVN
}

#[derive(Drop, Debug)]
pub struct TcbInfoV3TcbLevelItem {
    pub tcb: TcbInfoV3TcbLevel,
    pub tcb_date: OffsetDateTime,
    pub tcb_status: ByteArray,
    pub advisory_ids: Option<Span<ByteArray>>,
}

#[derive(Drop, Debug)]
pub struct TcbInfoV3TcbLevel {
    pub sgxtcbcomponents: Array<TcbComponent>,
    pub pcesvn: u16,
    pub tdxtcbcomponents: Option<Array<TcbComponent>>,
}

#[derive(Drop, Debug)]
pub struct TcbComponent {
    pub svn: u8, // SVN of TCB Component.
    pub category: Option<ByteArray>, // Category of TCB Component (e.g. BIOS, OS/VMM).
    pub type_: Option<
        ByteArray,
    > // Type of TCB Component (e.g. SGX Late Microcode Update, TXT SINIT).
}
