use x509_parser::certificate::X509Certificate;
use x509_parser::revocation_list::CertificateRevocationList;
use crate::types::enclave_identity::EnclaveIdentityV2;
use crate::types::tcbinfo::TcbInfoV3;
use crate::utils::cert::{parse_crl_der, parse_x509_der};

#[derive(Drop)]
pub struct IntelCollateral {
    pub tcbinfo: Option<TcbInfoV3>,
    pub qeidentity: Option<EnclaveIdentityV2>,
    pub sgx_intel_root_ca_der: Option<Span<u8>>,
    pub sgx_tcb_signing_der: Option<Span<u8>>,
    pub sgx_pck_certchain_der: Option<Span<u8>>,
    pub sgx_intel_root_ca_crl_der: Option<Span<u8>>,
    pub sgx_pck_processor_crl_der: Option<Span<u8>>,
    pub sgx_pck_platform_crl_der: Option<Span<u8>>,
}

// builder pattern for IntelCollateralV3
impl IntelCollateralDefault of Default<IntelCollateral> {
    fn default() -> IntelCollateral {
        IntelCollateralImpl::new()
    }
}

#[generate_trait]
pub impl IntelCollateralImpl of IntelCollateralTrait {
    fn new() -> IntelCollateral {
        IntelCollateral {
            tcbinfo: None,
            qeidentity: None,
            sgx_intel_root_ca_der: None,
            sgx_tcb_signing_der: None,
            sgx_pck_certchain_der: None,
            sgx_intel_root_ca_crl_der: None,
            sgx_pck_processor_crl_der: None,
            sgx_pck_platform_crl_der: None,
        }
    }

    fn get_tcbinfov3(self: @IntelCollateral) -> @TcbInfoV3 {
        match self.tcbinfo {
            Some(tcbinfo) => {
                assert!(tcbinfo.tcb_info.version == @3);
                tcbinfo
            },
            None => panic!("TCB Info V3 not set"),
        }
    }

    fn set_tcbinfo(ref self: IntelCollateral, tcbinfo: TcbInfoV3) {
        self.tcbinfo = Option::Some(tcbinfo);
    }

    fn get_qeidentity(self: @IntelCollateral) -> @EnclaveIdentityV2 {
        match self.qeidentity {
            Some(qeidentity) => qeidentity,
            None => panic!("QE Identity V2 not set"),
        }
    }

    fn set_qeidentity(ref self: IntelCollateral, qeidentity: EnclaveIdentityV2) {
        self.qeidentity = Option::Some(qeidentity);
    }

    fn get_sgx_intel_root_ca(self: @IntelCollateral) -> X509Certificate {
        match self.sgx_intel_root_ca_der {
            Option::Some(der) => {
                let cert = parse_x509_der(der);
                cert
            },
            Option::None => panic!("SGX Intel Root CA not set"),
        }
    }

    fn set_intel_root_ca_der(ref self: IntelCollateral, intel_root_ca_der: @Span<u8>) {
        self.sgx_intel_root_ca_der = Option::Some(intel_root_ca_der.clone());
    }

    fn get_sgx_tcb_signing(self: @IntelCollateral) -> X509Certificate {
        match self.sgx_tcb_signing_der {
            Option::Some(der) => {
                let cert = parse_x509_der(der);
                cert
            },
            Option::None => panic!("SGX TCB Signing Cert not set"),
        }
    }

    fn set_sgx_tcb_signing_pem(ref self: IntelCollateral, sgx_tcb_signing_pem: Span<u8>) {
        // convert pem to der
        // CAIRO: PEM parsing is not yet implemented. As a temporary workaround, we use
        // pre-converted DER data. This assumes the PEM data matches signing_cert.pem.
        self.sgx_tcb_signing_der = Option::Some(sgx_tcb_signing_pem);
    }

    fn get_sgx_intel_root_ca_crl(self: @IntelCollateral) -> Option<CertificateRevocationList> {
        match self.sgx_intel_root_ca_crl_der {
            Option::Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                Option::Some(crl)
            },
            Option::None => Option::None,
        }
    }

    fn set_sgx_intel_root_ca_crl_der(
        ref self: IntelCollateral, sgx_intel_root_ca_crl_der: @Span<u8>,
    ) {
        self.sgx_intel_root_ca_crl_der = Option::Some(sgx_intel_root_ca_crl_der.clone());
    }

    fn get_sgx_pck_processor_crl(self: @IntelCollateral) -> Option<CertificateRevocationList> {
        match self.sgx_pck_processor_crl_der {
            Option::Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                Option::Some(crl)
            },
            Option::None => Option::None,
        }
    }

    fn get_sgx_pck_platform_crl(self: @IntelCollateral) -> Option<CertificateRevocationList> {
        match self.sgx_pck_platform_crl_der {
            Option::Some(crl_der) => {
                let crl = parse_crl_der(crl_der);
                Option::Some(crl)
            },
            Option::None => Option::None,
        }
    }

    fn set_sgx_platform_crl_der(ref self: IntelCollateral, sgx_pck_platform_crl_der: @Span<u8>) {
        self.sgx_pck_platform_crl_der = Option::Some(sgx_pck_platform_crl_der.clone());
    }
}
