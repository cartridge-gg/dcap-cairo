use x509_parser::certificate::X509Certificate;
use x509_parser::revocation_list::CertificateRevocationList;
use crate::types::collaterals::{IntelCollateral, IntelCollateralTrait};
use crate::utils::cert::{get_crl_uri, is_cert_revoked};

// CAIRO: Helper module for Intel CRL URI matching
mod cairo_crl_matching;
use cairo_crl_matching::{IntelCrl, match_intel_crl};

#[derive(Drop, Debug)]
pub struct SgxExtensionTcbLevel {
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
    pub cpusvn: [u8; 16],
}

#[derive(Drop, Debug)]
pub struct SgxExtensions {
    pub ppid: [u8; 16],
    pub tcb: SgxExtensionTcbLevel,
    pub pceid: [u8; 2],
    pub fmspc: [u8; 6],
    pub sgx_type: u32,
    pub platform_instance_id: Option<[u8; 16]>,
    pub configuration: Option<PckPlatformConfiguration>,
}

#[derive(Drop, Debug)]
pub struct PckPlatformConfiguration {
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

#[derive(Drop, Debug)]
pub struct IntelSgxCrls {
    pub sgx_root_ca_crl: Option<CertificateRevocationList>,
    pub sgx_pck_processor_crl: Option<CertificateRevocationList>,
    pub sgx_pck_platform_crl: Option<CertificateRevocationList>,
}

#[generate_trait]
pub impl IntelSgxCrlsImpl of IntelSgxCrlsTrait {
    fn new(
        sgx_root_ca_crl: Option<CertificateRevocationList>,
        sgx_pck_processor_crl: Option<CertificateRevocationList>,
        sgx_pck_platform_crl: Option<CertificateRevocationList>,
    ) -> IntelSgxCrls {
        IntelSgxCrls { sgx_root_ca_crl, sgx_pck_processor_crl, sgx_pck_platform_crl }
    }

    fn from_collaterals(collaterals: @IntelCollateral) -> IntelSgxCrls {
        let sgx_root_ca_crl = collaterals.get_sgx_intel_root_ca_crl();
        let sgx_pck_processor_crl = collaterals.get_sgx_pck_processor_crl();
        let sgx_pck_platform_crl = collaterals.get_sgx_pck_platform_crl();

        Self::new(sgx_root_ca_crl, sgx_pck_processor_crl, sgx_pck_platform_crl)
    }

    fn is_cert_revoked(self: @IntelSgxCrls, cert: @X509Certificate) -> bool {
        let crl = match get_crl_uri(cert) {
            Some(crl_uri) => {
                let mut crl_uri = *crl_uri;
                match match_intel_crl(ref crl_uri) {
                    Some(crl_type) => {
                        match crl_type {
                            IntelCrl::SgxPckPlatformCrl => self.sgx_pck_platform_crl,
                            IntelCrl::SgxPckProcessorCrl => self.sgx_pck_processor_crl,
                            IntelCrl::SgxRootCaCrl => self.sgx_root_ca_crl,
                        }
                    },
                    None => panic!("Unknown CRL URI"),
                }
            },
            None => panic!("No CRL URI found in certificate"),
        };
        let crl = match crl {
            Some(crl) => crl,
            None => panic!("CRL not provided"),
        };

        // check if the cert is revoked given the crl
        is_cert_revoked(cert, crl)
    }
}
