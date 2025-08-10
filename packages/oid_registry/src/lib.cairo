//! Ported from [`oid-registry`](https://crates.io/crates/oid-registry) v0.8.1.

use asn1::{Oid, OidTrait};

/// 2.5.4.3
pub fn oid_x509_common_name() -> Oid {
    OidTrait::new(@array![85, 4, 3].span())
}

/// 2.5.29.19
pub fn oid_x509_ext_basic_constraints() -> Oid {
    OidTrait::new(@array![85, 29, 19].span())
}

/// 2.5.29.31
pub fn oid_x509_ext_crl_distribution_points() -> Oid {
    OidTrait::new(@array![85, 29, 31].span())
}
