# `dcap-cairo`

Cairo port of [`dcap-rs`](https://github.com/automata-network/dcap-rs) for [DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) verification.

## Prerequisites

The project uses [Cairo v2.12.0](https://github.com/starkware-libs/cairo/releases/tag/v2.12.0).

To build the project, make sure [Scarb v2.12.0](https://github.com/software-mansion/scarb/releases/tag/v2.12.0) is installed:

```console
$ scarb --version
scarb 2.12.0 (639d0a65e 2025-08-04)
cairo: 2.12.0 (https://crates.io/crates/cairo-lang-compiler/2.12.0)
sierra: 1.7.0
```

To also run tests, the `cairo-test` Scarb extension is also needed:

```console
$ scarb cairo-test --version
cairo-test 2.12.0
```

## Packages

This repository contains the following Scarb packages:

- [`dcap`](./packages/dcap): Ported from [`dcap-rs`](https://github.com/automata-network/dcap-rs) at commit [`d847b8f`](https://github.com/automata-network/dcap-rs/commit/d847b8f75a493640c4881bdf67775250b6baefab).
- [`x509_parser`](./packages/x509_parser): Ported from [`x509-parser`](https://crates.io/crates/x509-parser) v0.17.0.
- [`der_parser`](./packages/der_parser): Ported from [`der-parser`](https://crates.io/crates/der-parser) v10.0.0.
- [`asn1`](./packages/asn1): Ported from [`asn1-rs`](https://crates.io/crates/asn1-rs) v0.7.1.
- [`nom`](./packages/nom): Ported from [`nom`](https://crates.io/crates/nom) v7.1.3.
- [`oid_registry`](./packages/oid_registry): Ported from [`oid-registry`](https://crates.io/crates/oid-registry) v0.8.1.
- [`time`](./packages/time): Ported from [`time`](https://crates.io/crates/time) v0.3.41.
- [`int_traits`](./packages/int_traits): Cairo helper traits for integer types.

Note that for each package, only parts relevant to DCAP quote verification are ported. These are _not_ complete Cairo ports from their Rust counterparts.

Nevertheless, the project tries to keep the Cairo code as close to the corresponding Rust code as possible, as doing so helps with keeping up-to-date with the upstream Rust code to benefit from any improvements and security fixes.

## Testing

Simply run `scarb test` to run all the tests in the workspace.

Notably, `test_verifyv4` performs a complete, end-to-end verification of a DCAP quote. To run this specific test case:

```console
$ scarb test --package dcap -f test_verifyv4
     Running cairo-test dcap
   Compiling test(dcap_unittest) dcap v0.1.0 (packages/dcap/Scarb.toml)
    Finished `dev` profile target(s) in 4 seconds
     Testing dcap
running 1 test
VerifiedOutput { quote_version: 4, tee_type: 129, tcb_status: TcbStatus::TcbOutOfDate(()), fmspc: [0, 128, 111, 5, 0, 0], quote_body: @QuoteBody::TD10QuoteBody(TD10ReportBody { tee_tcb_svn: [4, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], mrseam: [255, 201, 122, 136, 88, 118, 96, 251, 4, 225, 247, 200, 81, 48, 12, 150, 174, 11, 90, 70, 58, 196, 109, 3, 93, 22, 194, 217, 243, 109, 14, 209, 210, 55, 117, 188, 189, 39, 222, 178, 25, 227, 163, 204, 40, 2, 56, 149], mrsignerseam: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], seam_attributes: 0, td_attributes: 268435456, xfam: 393447, mrtd: [147, 91, 231, 116, 45, 216, 156, 106, 77, 246, 219, 168, 53, 61, 137, 4, 26, 224, 240, 82, 190, 239, 153, 59, 30, 127, 69, 36, 211, 188, 87, 101, 13, 242, 14, 85, 130, 21, 131, 82, 225, 36, 11, 63, 31, 237, 85, 216], mrconfigid: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], mrowner: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], mrownerconfig: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], rtmr0: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], rtmr1: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], rtmr2: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], rtmr3: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], report_data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }), advisory_ids: Option::Some(["INTEL-SA-00960", "INTEL-SA-00982", "INTEL-SA-00986"]) }
test dcap::tests::test_verifyv4 ... ok (gas usage est.: 828401522)
test result: ok. 1 passed; 0 failed; 0 ignored; 3 filtered out;
```

## Test data generation

In order to demonstrate feature parity, currently all the test data are derived from `dcap-rs`. Due to differences between Rust and Cairo, however, these test data have been pre-processed with [`dcap-cairo-cli`](https://github.com/cartridge-gg/dcap-cairo-cli), making it slightly difficult to verify the source of data.

The authenticity of test data can be verified by re-generating them using the CLI. This section provides instructions on doing exactly that.

First make sure [`dcap-cairo-cli`](https://github.com/cartridge-gg/dcap-cairo-cli) is properly installed, and that the `dcap-cairo` command is available.

Then, clone the `dcap-rs` repository (at commit `d847b8f75a493640c4881bdf67775250b6baefab`), ideally adjacent to the current repository like so:

```
├── dcap-cairo
└── dcap-rs
```

Assuming you're inside this repository right now, these commands will clone the `dcap-rs` repository and return to the directory containing both repositories:

```console
cd ..
git clone https://github.com/automata-network/dcap-rs
cd dcap-rs
git checkout d847b8f75a493640c4881bdf67775250b6baefab
cd ../
```

Now, delete all the existing Cairo test data:

```console
rm ./dcap-cairo/packages/dcap/src/data/*
```

Generate all the Cairo test data from `dcap-rs` and format the generated code:

```console
# Directly included binary
dcap-cairo preprocess include-bytes --input ./dcap-rs/data/pck_platform_crl.der --output ./dcap-cairo/packages/dcap/src/data/pck_platform_crl.cairo
dcap-cairo preprocess include-bytes --input ./dcap-rs/data/intel_root_ca_crl.der --output ./dcap-cairo/packages/dcap/src/data/intel_root_ca_crl.cairo
dcap-cairo preprocess include-bytes --input ./dcap-rs/data/Intel_SGX_Provisioning_Certification_RootCA.cer --output ./dcap-cairo/packages/dcap/src/data/Intel_SGX_Provisioning_Certification_RootCA.cairo

# Out-of-band PEM decoding
dcap-cairo preprocess pem --input ./dcap-rs/data/signing_cert.pem --output ./dcap-cairo/packages/dcap/src/data/signing_cert_der.cairo

# Out-of-band JSON parsing
dcap-cairo preprocess qeidentity --input ./dcap-rs/data/qeidentityv2_apiv4.json --output ./dcap-cairo/packages/dcap/src/data/qeidentityv2_apiv4.cairo
dcap-cairo preprocess tcbinfo --input ./dcap-rs/data/tcbinfov3_00806f050000.json --output ./dcap-cairo/packages/dcap/src/data/tcbinfov3_00806f050000.cairo

# Quote internal cert chain data format mutation
dcap-cairo preprocess quote --input ./dcap-rs/data/quote_tdx_00806f050000.dat --output ./quote_mutated.dat
dcap-cairo preprocess include-bytes --input ./quote_mutated.dat --output ./dcap-cairo/packages/dcap/src/data/quote_tdx_00806f050000.cairo
rm ./quote_mutated.dat

# Format the generated code
cd ./dcap-cairo
scarb fmt
```

Now, you can use `git status` to verify that the Git worktree is clean, meaning that the generated test data match exactly with the version controlled files.
