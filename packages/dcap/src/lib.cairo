pub mod constants;
pub mod data;

/// A Cairo-only module for handling collateral serialization in order to verify signatures. As
/// Intel signs over their JSON representation.
mod json;

pub mod types;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::data::{
        Intel_SGX_Provisioning_Certification_RootCA, intel_root_ca_crl, pck_platform_crl,
        qeidentityv2_apiv4, quote_tdx_00806f050000, signing_cert_der, tcbinfov3_00806f050000,
    };
    use crate::types::collaterals::IntelCollateralTrait;
    use crate::types::quotes::version_4::QuoteV4Trait;
    use crate::utils::quotes::version_4::verify_quote_dcapv4;

    // Pinned September 10th, 2024, 6:49am GMT
    // there's no need for constant sample collateral updates
    const PINNED_TIME: u64 = 1739419232;

    #[test]
    fn test_quotev4() {
        let quotev4_slice = quote_tdx_00806f050000::DATA.span();
        let quotev4 = QuoteV4Trait::from_bytes(quotev4_slice);
        assert_eq!(quotev4.header.version, 4);
    }

    #[test]
    fn test_verifyv4() {
        // let current_time = chrono::Utc::now().timestamp() as u64;

        let mut collaterals = IntelCollateralTrait::new();
        collaterals.set_tcbinfo(tcbinfov3_00806f050000::data());
        collaterals.set_qeidentity(qeidentityv2_apiv4::data());
        collaterals
            .set_intel_root_ca_der(@Intel_SGX_Provisioning_Certification_RootCA::DATA.span());
        collaterals.set_sgx_tcb_signing_pem(signing_cert_der::DATA.span());
        collaterals.set_sgx_intel_root_ca_crl_der(@intel_root_ca_crl::DATA.span());
        collaterals.set_sgx_platform_crl_der(@pck_platform_crl::DATA.span());
        // collaterals.set_sgx_processor_crl_der(include_bytes!("../data/pck_processor_crl.der"));

        let dcap_quote = QuoteV4Trait::from_bytes(quote_tdx_00806f050000::DATA.span());

        let verified_output = verify_quote_dcapv4(@dcap_quote, @collaterals, PINNED_TIME);

        println!("{:?}", verified_output);
    }
}
