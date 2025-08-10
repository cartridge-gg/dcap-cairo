pub mod cert;
pub mod collaterals;
pub mod enclave_identity;
pub mod quotes;
pub mod tcbinfo;
use quotes::body::QuoteBody;

#[derive(Drop, Debug, PartialEq)]
pub enum TcbStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized,
}

#[generate_trait]
pub impl TcbStatusImpl of TcbStatusTrait {
    fn from_str(s: @ByteArray) -> TcbStatus {
        if s == @"UpToDate" {
            TcbStatus::OK
        } else if s == @"SWHardeningNeeded" {
            TcbStatus::TcbSwHardeningNeeded
        } else if s == @"ConfigurationAndSWHardeningNeeded" {
            TcbStatus::TcbConfigurationAndSwHardeningNeeded
        } else if s == @"ConfigurationNeeded" {
            TcbStatus::TcbConfigurationNeeded
        } else if s == @"OutOfDate" {
            TcbStatus::TcbOutOfDate
        } else if s == @"OutOfDateConfigurationNeeded" {
            TcbStatus::TcbOutOfDateConfigurationNeeded
        } else if s == @"Revoked" {
            TcbStatus::TcbRevoked
        } else {
            TcbStatus::TcbUnrecognized
        }
    }
}

#[derive(Drop, Debug)]
pub struct VerifiedOutput {
    pub quote_version: u16,
    pub tee_type: u32,
    pub tcb_status: TcbStatus,
    pub fmspc: [u8; 6],
    pub quote_body: @QuoteBody,
    pub advisory_ids: Option<Span<ByteArray>>,
}
