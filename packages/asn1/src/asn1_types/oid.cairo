use crate::*;

/// Object ID (OID) representation which can be relative or non-relative.
#[derive(Drop, Debug, Copy, PartialEq)]
pub struct Oid {
    asn1: @Span<u8>,
    relative: bool,
}

pub impl AnyTryIntoOid of Into<Any, Result<Oid, Error>> {
    fn into(self: Any) -> Result<Oid, Error> {
        // check that any.data.last().unwrap() >> 7 == 0u8
        Ok(OidTrait::new(self.data))
    }
}

pub impl OidCheckDerConstraints of CheckDerConstraints<Oid> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        any.header.assert_primitive()?;
        any.header.length.assert_definite()?;
        Ok(())
    }
}

#[generate_trait]
pub impl OidImpl of OidTrait {
    /// Create an OID from the ASN.1 DER encoded form. See the [module documentation](index.html)
    /// for other ways to create oids.
    const fn new(asn1: @Span<u8>) -> Oid {
        Oid { asn1, relative: false }
    }
}
