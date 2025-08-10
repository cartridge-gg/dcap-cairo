use asn1::{
    Any, BerParser, Boolean, BooleanCheckDerConstraints, BooleanTrait, Enumerated, Error, FromDer,
    FromDerViaAny, OctetString, Oid, OidTrait, Sequence, SequenceIteratorIterTrait,
    SequenceIteratorTrait, U32CheckDerConstraints,
};
use core::num::traits::Bounded;
use oid_registry::{oid_x509_common_name, oid_x509_ext_crl_distribution_points};
use x509_parser::certificate::{TbsCertificateTrait, X509Certificate};
use x509_parser::extensions::{
    DistributionPointName, GeneralName, ParsedExtension, X509ExtensionTrait,
};
use x509_parser::revocation_list::{
    CertificateRevocationList, CertificateRevocationListTrait, TbsCertListTrait,
};
use x509_parser::time::ASN1TimeTrait;
use x509_parser::x509::{AttributeTypeAndValueTrait, X509NameTrait};
use crate::constants::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use crate::types::cert::{PckPlatformConfiguration, SgxExtensionTcbLevel, SgxExtensions};
use crate::types::tcbinfo::{TcbComponent, TcbInfoV3};
use crate::types::{TcbStatus, TcbStatusTrait};
use crate::utils::crypto::verify_p256_signature_der;

pub fn parse_crl_der(raw_bytes: @Span<u8>) -> CertificateRevocationList {
    let (_, crl) = FromDer::<CertificateRevocationList>::from_der(raw_bytes).unwrap();
    crl
}

pub fn parse_x509_der(raw_bytes: @Span<u8>) -> X509Certificate {
    let (_, cert) = FromDer::<X509Certificate>::from_der(raw_bytes).unwrap();
    cert
}

pub fn parse_x509_der_multi(raw_bytes: @Span<u8>) -> Array<X509Certificate> {
    let mut certs = ArrayTrait::new();
    let mut i = raw_bytes.clone();
    while !i.is_empty() {
        let (j, cert) = FromDer::<X509Certificate>::from_der(@i).unwrap();
        certs.append(cert);
        i = j.clone();
    }
    certs
}

pub fn verify_certificate(
    cert: @X509Certificate, signer_cert: @X509Certificate, current_time: u64,
) -> bool {
    // verifies that the certificate is unexpired
    let issue_date: u64 = cert
        .tbs_certificate
        .validity()
        .not_before
        .timestamp()
        .try_into()
        .unwrap();
    let expiry_date: u64 = cert
        .tbs_certificate
        .validity()
        .not_after
        .timestamp()
        .try_into()
        .unwrap();
    if (current_time < issue_date) || (current_time > expiry_date) {
        return false;
    }

    // verifies that the certificate is valid
    let data: @Span = *cert.tbs_certificate.raw;
    let signature: @Span = cert.signature_value.data;
    let public_key: @Span = signer_cert.tbs_certificate.public_key().subject_public_key.data;

    // make sure that the issuer is the signer
    if cert.tbs_certificate.issuer() != signer_cert.tbs_certificate.subject() {
        return false;
    }

    verify_p256_signature_der(data, signature, public_key)
}

pub fn verify_crl(
    crl: @CertificateRevocationList, signer_cert: @X509Certificate, current_time: u64,
) -> bool {
    // verifies that the crl is unexpired
    let issue_date: u64 = crl.last_update().timestamp().try_into().unwrap();
    let expiry_date: u64 = if let Some(next_update) = crl.next_update() {
        next_update.timestamp().try_into().unwrap()
    } else {
        // next update field is optional
        Bounded::<u64>::MAX
    };

    if (current_time < issue_date) || (current_time > expiry_date) {
        return false;
    }

    // verifies that the crl is valid
    let data = crl.tbs_cert_list.data();
    let signature = crl.signature_value.data;
    let public_key = signer_cert.tbs_certificate.public_key().subject_public_key.data;
    // make sure that the issuer is the signer
    if crl.issuer() != signer_cert.tbs_certificate.subject() {
        return false;
    }
    verify_p256_signature_der(data, signature, public_key)
}

// we'll just verify that the certchain signature matches, any other checks will be done by the
// caller
pub fn verify_certchain_signature(
    certs: Span<X509Certificate>, root_cert: @X509Certificate, current_time: u64,
) -> bool {
    // verify that the cert chain is valid
    let mut iter = certs;
    let mut prev_cert = iter.pop_front().unwrap();
    for cert in iter {
        // verify that the previous cert signed the current cert
        if !verify_certificate(prev_cert, cert, current_time) {
            return false;
        }
        prev_cert = cert;
    }
    // verify that the root cert signed the last cert
    verify_certificate(prev_cert, root_cert, current_time)
}

pub fn is_cert_revoked(cert: @X509Certificate, crl: @CertificateRevocationList) -> bool {
    for entry in crl.tbs_cert_list.revoked_certificates.span() {
        if entry.user_certificate == cert.tbs_certificate.serial {
            return true;
        }
    }
    false
}

pub fn get_x509_subject_cn(cert: @X509Certificate) -> @Span<u8> {
    let subject = cert.tbs_certificate.subject();
    let cn = subject.find_attribute_by_oid(oid_x509_common_name()).unwrap();

    // CAIRO: Changed to return data directly since it's only used for comparison anyway
    *cn.attr_value().data
}

pub fn get_x509_issuer_cn(cert: @X509Certificate) -> @Span<u8> {
    let issuer = cert.tbs_certificate.issuer();
    let cn = issuer.find_attribute_by_oid(oid_x509_common_name()).unwrap();

    // CAIRO: Changed to return data directly since it's only used for comparison anyway
    *cn.attr_value().data
}

pub fn get_crl_uri(cert: @X509Certificate) -> Option<@Span<u8>> {
    let crl_ext = cert
        .tbs_certificate
        .get_extension_unique(@oid_x509_ext_crl_distribution_points())
        .unwrap()
        .unwrap();
    let crl_uri = match crl_ext.parsed_extension() {
        ParsedExtension::CRLDistributionPoints(crls) => {
            if crls.points.len() == 0 {
                None
            } else {
                match crls.points.at(0).distribution_point {
                    Some(distribution_point_name) => match distribution_point_name {
                        DistributionPointName::FullName(uri) => {
                            let uri = uri.at(0);
                            match uri {
                                GeneralName::URI(uri) => Some(*uri),
                            }
                        },
                        _ => None,
                    },
                    None => None,
                }
            }
        },
        _ => panic!("unreachable"),
    };
    crl_uri
}

pub fn extract_sgx_extension(cert: @X509Certificate) -> SgxExtensions {
    // https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

    // <SGX Extensions OID>:
    //     <PPID OID>: <PPID value>
    //     <TCB OID>:
    //          <SGX TCB Comp01 SVN OID>: <SGX TCB Comp01 SVN value>
    //          <SGX TCB Comp02 SVN OID>: <SGX TCB Comp02 SVN value>
    //          …
    //          <SGX TCB Comp16 SVN OID>: <SGX TCB Comp16 SVN value>
    //          <PCESVN OID>: <PCESVN value>
    //          <CPUSVN OID>: <CPUSVN value>
    //     <PCE-ID OID>: <PCE-ID value>
    //     <FMSPC OID>: <FMSPC value>
    //     <SGX Type OID>: <SGX Type value>
    //     <PlatformInstanceID OID>: <PlatformInstanceID value>
    //     <Configuration OID>:
    //          <Dynamic Platform OID>: <Dynamic Platform flag value>
    //          <Cached Keys OID>: <Cached Keys flag value>
    //          <SMT Enabled OID>: <SMT Enabled flag value>

    // SGX Extensions       | 1.2.840.113741.1.13.1      | mandatory | ASN.1 Sequence
    // PPID                 | 1.2.840.113741.1.13.1.1    | mandatory | ASN.1 Octet String
    // TCB                  | 1.2.840.113741.1.13.1.2    | mandatory | ASN.1 Sequence
    // SGX TCB Comp01 SVN   | 1.2.840.113741.1.13.1.2.1  | mandatory | ASN.1 Integer
    // SGX TCB Comp02 SVN   | 1.2.840.113741.1.13.1.2.2  | mandatory | ASN.1 Integer
    // ...
    // SGX TCB Comp16 SVN   | 1.2.840.113741.1.13.1.2.16 | mandatory | ASN.1 Integer
    // PCESVN               | 1.2.840.113741.1.13.1.2.17 | mandatory | ASN.1 Integer
    // CPUSVN               | 1.2.840.113741.1.13.1.2.18 | mandatory | ASN.1 Integer
    // PCE-ID               | 1.2.840.113741.1.13.1.3    | mandatory | ASN.1 Octet String
    // FMSPC                | 1.2.840.113741.1.13.1.4    | mandatory | ASN.1 Octet String
    // SGX Type             | 1.2.840.113741.1.13.1.5    | mandatory | ASN.1 Enumerated
    // Platform Instance ID | 1.2.840.113741.1.13.1.6    | optional  | ASN.1 Octet String
    // Configuration        | 1.2.840.113741.1.13.1.7    | optional  | ASN.1 Sequence
    // Dynamic Platform     | 1.2.840.113741.1.13.1.7.1  | optional  | ASN.1 Boolean
    // Cached Keys          | 1.2.840.113741.1.13.1.7.2  | optional  | ASN.1 Boolean
    // SMT Enabled          | 1.2.840.113741.1.13.1.7.3  | optional  | ASN.1 Boolean

    let sgx_extensions_bytes = cert
        .tbs_certificate
        .get_extension_unique(@oid_sgx_extension())
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = FromDerViaAny::<Sequence, Error>::from_der(*sgx_extensions_bytes)
        .unwrap();

    // we'll process the sgx extensions here...
    let mut i = SequenceIteratorTrait::<Any, BerParser, Error>::new(sgx_extensions.content);

    // let's define the required information to create the SgxExtensions struct
    let mut ppid: Option<[u8; 16]> = None;

    let mut tcb: Option<SgxExtensionTcbLevel> = None;
    let mut pceid: Option<[u8; 2]> = None;
    let mut fmspc: Option<[u8; 6]> = None;
    let mut sgx_type: Option<u32> = None;
    let mut platform_instance_id: Option<[u8; 16]> = None;
    let mut configuration: Option<PckPlatformConfiguration> = None;

    while let Some(current_sequence) = i.next() {
        let (j, current_oid) = FromDerViaAny::<Oid, Error>::from_der(current_sequence.unwrap().data)
            .unwrap();

        if current_oid == oid_sgx_extension_ppid() {
            let (k, ppid_bytes) = FromDerViaAny::<OctetString, Error>::from_der(j).unwrap();

            assert!(k.is_empty());

            let mut iter = ppid_bytes.data;
            ppid =
                Some(
                    [
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                        *iter.pop_front().unwrap(), *iter.pop_front().unwrap(),
                    ],
                );
        } else if current_oid == oid_sgx_extension_tcb() {
            let (k, tcb_sequence) = FromDerViaAny::<Sequence, Error>::from_der(j).unwrap();
            assert!(k.is_empty());
            // iterate through from 1 - 18
            let (k, sgxtcbcomp01svn) = get_asn1_uint64(
                tcb_sequence.content, oid_sgx_extension_tcb_comp01_svn(),
            );
            let (k, sgxtcbcomp02svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp02_svn());
            let (k, sgxtcbcomp03svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp03_svn());
            let (k, sgxtcbcomp04svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp04_svn());
            let (k, sgxtcbcomp05svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp05_svn());
            let (k, sgxtcbcomp06svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp06_svn());
            let (k, sgxtcbcomp07svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp07_svn());
            let (k, sgxtcbcomp08svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp08_svn());
            let (k, sgxtcbcomp09svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp09_svn());
            let (k, sgxtcbcomp10svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp10_svn());
            let (k, sgxtcbcomp11svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp11_svn());
            let (k, sgxtcbcomp12svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp12_svn());
            let (k, sgxtcbcomp13svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp13_svn());
            let (k, sgxtcbcomp14svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp14_svn());
            let (k, sgxtcbcomp15svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp15_svn());
            let (k, sgxtcbcomp16svn) = get_asn1_uint64(k, oid_sgx_extension_tcb_comp16_svn());
            let (k, pcesvn) = get_asn1_uint64(k, oid_sgx_extension_tcb_pcesvn());
            let (k, mut cpusvn) = get_asn1_bytes(k, oid_sgx_extension_tcb_cpusvn());

            assert!(k.is_empty());
            // copy the bytes into the tcb struct
            tcb =
                Some(
                    SgxExtensionTcbLevel {
                        sgxtcbcomp01svn: sgxtcbcomp01svn.try_into().unwrap(),
                        sgxtcbcomp02svn: sgxtcbcomp02svn.try_into().unwrap(),
                        sgxtcbcomp03svn: sgxtcbcomp03svn.try_into().unwrap(),
                        sgxtcbcomp04svn: sgxtcbcomp04svn.try_into().unwrap(),
                        sgxtcbcomp05svn: sgxtcbcomp05svn.try_into().unwrap(),
                        sgxtcbcomp06svn: sgxtcbcomp06svn.try_into().unwrap(),
                        sgxtcbcomp07svn: sgxtcbcomp07svn.try_into().unwrap(),
                        sgxtcbcomp08svn: sgxtcbcomp08svn.try_into().unwrap(),
                        sgxtcbcomp09svn: sgxtcbcomp09svn.try_into().unwrap(),
                        sgxtcbcomp10svn: sgxtcbcomp10svn.try_into().unwrap(),
                        sgxtcbcomp11svn: sgxtcbcomp11svn.try_into().unwrap(),
                        sgxtcbcomp12svn: sgxtcbcomp12svn.try_into().unwrap(),
                        sgxtcbcomp13svn: sgxtcbcomp13svn.try_into().unwrap(),
                        sgxtcbcomp14svn: sgxtcbcomp14svn.try_into().unwrap(),
                        sgxtcbcomp15svn: sgxtcbcomp15svn.try_into().unwrap(),
                        sgxtcbcomp16svn: sgxtcbcomp16svn.try_into().unwrap(),
                        pcesvn: pcesvn.try_into().unwrap(),
                        cpusvn: [
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                            *cpusvn.pop_front().unwrap(), *cpusvn.pop_front().unwrap(),
                        ],
                    },
                )
        } else if current_oid == oid_sgx_extension_pceid() {
            let (k, mut pceid_bytes) = FromDerViaAny::<OctetString, Error>::from_der(j).unwrap();
            assert!(k.is_empty());
            pceid =
                Some(
                    [
                        *pceid_bytes.data.pop_front().unwrap(),
                        *pceid_bytes.data.pop_front().unwrap(),
                    ],
                );
        } else if current_oid == oid_sgx_extension_fmspc() {
            let (k, mut fmspc_bytes) = FromDerViaAny::<OctetString, Error>::from_der(j).unwrap();
            assert!(k.is_empty());
            fmspc =
                Some(
                    [
                        *fmspc_bytes.data.pop_front().unwrap(),
                        *fmspc_bytes.data.pop_front().unwrap(),
                        *fmspc_bytes.data.pop_front().unwrap(),
                        *fmspc_bytes.data.pop_front().unwrap(),
                        *fmspc_bytes.data.pop_front().unwrap(),
                        *fmspc_bytes.data.pop_front().unwrap(),
                    ],
                );
        } else if current_oid == oid_sgx_extension_sgx_type() {
            // CAIRO: Changed from `Enumerated` to using `u32` directly. The same constraints apply.
            let (k, sgx_type_enum) = FromDerViaAny::<Enumerated, Error>::from_der(j).unwrap();
            assert!(k.is_empty());
            sgx_type = Some(sgx_type_enum.data);
        } else if current_oid == oid_sgx_extension_platform_instance_id() {
            let (k, mut platform_instance_id_bytes) = FromDerViaAny::<
                OctetString, Error,
            >::from_der(j)
                .unwrap();
            assert!(k.is_empty());
            platform_instance_id =
                Some(
                    [
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                        *platform_instance_id_bytes.data.pop_front().unwrap(),
                    ],
                );
        } else if current_oid == oid_sgx_extension_configuration() {
            let (k, configuration_seq) = FromDerViaAny::<Sequence, Error>::from_der(j).unwrap();
            assert!(k.is_empty());
            let mut dynamic_platform: Option<bool> = None;
            let mut cached_keys: Option<bool> = None;
            let mut smt_enabled: Option<bool> = None;

            // iterate through from 1 - 3, note that some of them might be optional.
            let mut k = SequenceIteratorTrait::<
                Any, BerParser, Error,
            >::new(configuration_seq.content);
            while let Some(asn1_seq) = k.next() {
                let (l, current_oid) = FromDerViaAny::<Oid, Error>::from_der(asn1_seq.unwrap().data)
                    .unwrap();
                if current_oid == oid_sgx_extension_configuration_dynamic_platform() {
                    let (l, dynamic_platform_bool) = FromDerViaAny::<Boolean, Error>::from_der(l)
                        .unwrap();
                    assert!(l.is_empty());
                    dynamic_platform = Some(dynamic_platform_bool.bool());
                } else if current_oid == oid_sgx_extension_configuration_cached_keys() {
                    let (l, cached_keys_bool) = FromDerViaAny::<Boolean, Error>::from_der(l)
                        .unwrap();
                    assert!(l.is_empty());
                    cached_keys = Some(cached_keys_bool.bool());
                } else if current_oid == oid_sgx_extension_configuration_smt_enabled() {
                    let (l, smt_enabled_bool) = FromDerViaAny::<Boolean, Error>::from_der(l)
                        .unwrap();
                    assert!(l.is_empty());
                    smt_enabled = Some(smt_enabled_bool.bool());
                } else {
                    panic!("Unknown OID: {:?}", current_oid);
                }
            }

            configuration =
                Some(PckPlatformConfiguration { dynamic_platform, cached_keys, smt_enabled });
        } else {
            panic!("Unknown OID: {:?}", current_oid);
        }
    }

    let ppid = match ppid {
        Some(value) => value,
        None => { panic!("SGX extension ppid missing") },
    };

    let tcb = match tcb {
        Some(value) => value,
        None => { panic!("SGX extension tcb missing") },
    };

    let pceid = match pceid {
        Some(value) => value,
        None => { panic!("SGX extension pceid missing") },
    };

    let fmspc = match fmspc {
        Some(value) => value,
        None => { panic!("SGX extension fmspc missing") },
    };

    let sgx_type = match sgx_type {
        Some(value) => value,
        None => { panic!("SGX extension sgx_type missing") },
    };

    SgxExtensions { ppid, tcb, pceid, fmspc, sgx_type, platform_instance_id, configuration }
}

// Slightly modified from
// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181
pub fn get_sgx_tdx_fmspc_tcbstatus_v3(
    tee_type: u32, sgx_extensions: @SgxExtensions, tee_tcb_svn: @[u8; 16], tcbinfov3: @TcbInfoV3,
) -> (TcbStatus, TcbStatus, Option<Span<ByteArray>>) {
    // we'll make sure the tcbinforoot is valid
    // check that fmspc is valid
    // check that pceid is valid

    // convert tcbinfo fmspc and pceid from string to bytes for comparison
    assert!(sgx_extensions.fmspc.span() == *tcbinfov3.tcb_info.fmspc, "FMSPC mismatch");
    assert!(sgx_extensions.pceid.span() == *tcbinfov3.tcb_info.pce_id, "PCE ID mismatch");

    let mut sgx_tcb_status = TcbStatus::TcbUnrecognized;
    let mut tdx_tcb_status = TcbStatus::TcbUnrecognized;

    let extension_pcesvn = sgx_extensions.tcb.pcesvn;
    let mut advisory_ids = Option::None;

    for tcb_level in tcbinfov3.tcb_info.tcb_levels {
        if sgx_tcb_status == TcbStatus::TcbUnrecognized {
            let sgxtcbcomponents_ok = match_sgxtcbcomp(
                sgx_extensions, tcb_level.tcb.sgxtcbcomponents,
            );
            let pcesvn_ok = extension_pcesvn >= tcb_level.tcb.pcesvn;
            if sgxtcbcomponents_ok && pcesvn_ok {
                sgx_tcb_status = TcbStatusTrait::from_str(tcb_level.tcb_status);
                if tee_type == SGX_TEE_TYPE {
                    // CAIRO: Temporarily hard-coded `advisory_ids` to `None`.
                    // TODO: Implement `advisory_ids`.
                    advisory_ids = match tcb_level.advisory_ids {
                        Some(advisory_ids) => Some(*advisory_ids),
                        None => None,
                    };
                }
            }
        }
        if (sgx_tcb_status != TcbStatus::TcbUnrecognized || sgx_tcb_status != TcbStatus::TcbRevoked)
            && !is_empty(tee_tcb_svn) {
            let tdxtcbcomponents_ok = match tcb_level.tcb.tdxtcbcomponents {
                Option::Some(tdxtcbcomponents) => {
                    check_tdx_components(tee_tcb_svn, tdxtcbcomponents.span())
                },
                Option::None => true,
            };
            if tdxtcbcomponents_ok {
                tdx_tcb_status = TcbStatusTrait::from_str(tcb_level.tcb_status);
                if tee_type == TDX_TEE_TYPE {
                    // CAIRO: Temporarily hard-coded `advisory_ids` to `None`.
                    // TODO: Implement `advisory_ids`.
                    advisory_ids = match tcb_level.advisory_ids {
                        Some(advisory_ids) => Some(*advisory_ids),
                        None => None,
                    };
                }
                break;
            }
        }
    }
    (sgx_tcb_status, tdx_tcb_status, advisory_ids)
}

fn is_empty(slice: @[u8; 16]) -> bool {
    for byte in slice {
        if byte != @0 {
            return false;
        }
    }
    true
}

fn match_sgxtcbcomp(
    sgx_extensions: @SgxExtensions, sgxtcbcomponents: @Array<TcbComponent>,
) -> bool {
    let extension_tcbcomponents = extension_to_tcbcomponents(sgx_extensions.tcb);
    // Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16)
    // with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
    // If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values
    // in TCB Level, then return true.
    // Otherwise, return false.
    let ext_span = extension_tcbcomponents.span();
    let tcb_span = sgxtcbcomponents.span();

    let min_len = if ext_span.len() < tcb_span.len() {
        ext_span.len()
    } else {
        tcb_span.len()
    };

    let mut i = 0;
    loop {
        if i >= min_len {
            break true;
        }
        if ext_span[i].svn < tcb_span[i].svn {
            break false;
        }
        i += 1;
    }
}

fn extension_to_tcbcomponents(extension: @SgxExtensionTcbLevel) -> Array<TcbComponent> {
    let mut components = array![];
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp01svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp02svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp03svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp04svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp05svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp06svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp07svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp08svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp09svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp10svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp11svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp12svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp13svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp14svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp15svn, category: Option::None, type_: Option::None,
            },
        );
    components
        .append(
            TcbComponent {
                svn: *extension.sgxtcbcomp16svn, category: Option::None, type_: Option::None,
            },
        );
    components
}

// CAIRO: Added extra function to handle Rust iters.
fn check_tdx_components(tee_tcb_svn: @[u8; 16], tdxtcbcomponents: Span<TcbComponent>) -> bool {
    let tee_span = (*tee_tcb_svn).span();
    let tdx_span = tdxtcbcomponents;

    let min_len = if tee_span.len() < tdx_span.len() {
        tee_span.len()
    } else {
        tdx_span.len()
    };

    let mut i = 0;
    loop {
        if i >= min_len {
            break true;
        }
        if *tee_span[i] < *tdx_span[i].svn {
            break false;
        }
        i += 1;
    }
}

fn get_asn1_uint64(bytes: @Span<u8>, oid_str: Oid) -> (@Span<u8>, u64) {
    let (k, asn1_seq) = FromDerViaAny::<Sequence, Error>::from_der(bytes).unwrap();
    let (l, asn1_oid) = FromDerViaAny::<Oid, Error>::from_der(asn1_seq.content).unwrap();
    assert!(oid_str == asn1_oid);
    let (l, asn1_int) = FromDerViaAny::<u32, Error>::from_der(l).unwrap();
    assert!(l.is_empty());
    (k, asn1_int.into())
}

fn get_asn1_bytes(bytes: @Span<u8>, oid_str: Oid) -> (@Span<u8>, Span<u8>) {
    let (k, asn1_seq) = FromDerViaAny::<Sequence, Error>::from_der(bytes).unwrap();
    let (l, asn1_oid) = FromDerViaAny::<Oid, Error>::from_der(asn1_seq.content).unwrap();
    assert!(oid_str == asn1_oid);
    let (l, asn1_bytes) = FromDerViaAny::<OctetString, Error>::from_der(l).unwrap();
    assert!(l.is_empty());
    (k, asn1_bytes.data)
}

/// 1.2.840.113741.1.13.1
fn oid_sgx_extension() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1].span())
}

/// 1.2.840.113741.1.13.1.1
fn oid_sgx_extension_ppid() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 1].span())
}

/// 1.2.840.113741.1.13.1.2
fn oid_sgx_extension_tcb() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2].span())
}

/// 1.2.840.113741.1.13.1.2.1
fn oid_sgx_extension_tcb_comp01_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 1].span())
}

/// 1.2.840.113741.1.13.1.2.2
fn oid_sgx_extension_tcb_comp02_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 2].span())
}

/// 1.2.840.113741.1.13.1.2.3
fn oid_sgx_extension_tcb_comp03_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 3].span())
}

/// 1.2.840.113741.1.13.1.2.4
fn oid_sgx_extension_tcb_comp04_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 4].span())
}

/// 1.2.840.113741.1.13.1.2.5
fn oid_sgx_extension_tcb_comp05_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 5].span())
}

/// 1.2.840.113741.1.13.1.2.6
fn oid_sgx_extension_tcb_comp06_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 6].span())
}

/// 1.2.840.113741.1.13.1.2.7
fn oid_sgx_extension_tcb_comp07_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 7].span())
}

/// 1.2.840.113741.1.13.1.2.8
fn oid_sgx_extension_tcb_comp08_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 8].span())
}

/// 1.2.840.113741.1.13.1.2.9
fn oid_sgx_extension_tcb_comp09_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 9].span())
}

/// 1.2.840.113741.1.13.1.2.10
fn oid_sgx_extension_tcb_comp10_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 10].span())
}

/// 1.2.840.113741.1.13.1.2.11
fn oid_sgx_extension_tcb_comp11_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 11].span())
}

/// 1.2.840.113741.1.13.1.2.12
fn oid_sgx_extension_tcb_comp12_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 12].span())
}

/// 1.2.840.113741.1.13.1.2.13
fn oid_sgx_extension_tcb_comp13_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 13].span())
}

/// 1.2.840.113741.1.13.1.2.14
fn oid_sgx_extension_tcb_comp14_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 14].span())
}

/// 1.2.840.113741.1.13.1.2.15
fn oid_sgx_extension_tcb_comp15_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 15].span())
}

/// 1.2.840.113741.1.13.1.2.16
fn oid_sgx_extension_tcb_comp16_svn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 16].span())
}

/// 1.2.840.113741.1.13.1.2.17
fn oid_sgx_extension_tcb_pcesvn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 17].span())
}

/// 1.2.840.113741.1.13.1.2.18
fn oid_sgx_extension_tcb_cpusvn() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 2, 18].span())
}

/// 1.2.840.113741.1.13.1.3
fn oid_sgx_extension_pceid() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 3].span())
}

/// 1.2.840.113741.1.13.1.4
fn oid_sgx_extension_fmspc() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 4].span())
}

/// 1.2.840.113741.1.13.1.5
fn oid_sgx_extension_sgx_type() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 5].span())
}

/// 1.2.840.113741.1.13.1.6
fn oid_sgx_extension_platform_instance_id() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 6].span())
}

/// 1.2.840.113741.1.13.1.7
fn oid_sgx_extension_configuration() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 7].span())
}

/// 1.2.840.113741.1.13.1.7.1
fn oid_sgx_extension_configuration_dynamic_platform() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 7, 1].span())
}

/// 1.2.840.113741.1.13.1.7.2
fn oid_sgx_extension_configuration_cached_keys() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 7, 2].span())
}

/// 1.2.840.113741.1.13.1.7.3
fn oid_sgx_extension_configuration_smt_enabled() -> Oid {
    OidTrait::new(@array![42, 134, 72, 134, 248, 77, 1, 13, 1, 7, 3].span())
}
