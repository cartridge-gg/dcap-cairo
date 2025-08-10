use time::OffsetDateTime;

#[derive(Drop, Debug, Clone)]
pub struct EnclaveIdentityV2 {
    pub enclave_identity: EnclaveIdentityV2Inner,
    pub signature: Span<u8>,
}

#[derive(Drop, Debug, Clone)]
pub struct EnclaveIdentityV2Inner {
    pub id: ByteArray,
    pub version: u32,
    pub issue_date: OffsetDateTime,
    pub next_update: OffsetDateTime,
    pub tcb_evaluation_data_number: u32,
    pub miscselect: Span<u8>,
    pub miscselect_mask: Span<u8>,
    pub attributes: Span<u8>,
    pub attributes_mask: Span<u8>,
    pub mrsigner: Span<u8>,
    pub isvprodid: u16,
    pub tcb_levels: Span<EnclaveIdentityV2TcbLevelItem>,
}

#[derive(Drop, Debug, Clone)]
pub struct EnclaveIdentityV2TcbLevelItem {
    pub tcb: EnclaveIdentityV2TcbLevel,
    pub tcb_date: OffsetDateTime,
    pub tcb_status: ByteArray,
    pub advisory_ids: Option<Span<ByteArray>>,
}

#[derive(Drop, Debug, Clone)]
pub struct EnclaveIdentityV2TcbLevel {
    pub isvsvn: u16,
}
