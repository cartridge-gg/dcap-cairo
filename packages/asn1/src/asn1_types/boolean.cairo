use crate::*;

/// ASN.1 `BOOLEAN` type.
///
/// BER objects consider any non-zero value as `true`, and `0` as `false`.
///
/// DER objects must use value `0x0` (`false`) or `0xff` (`true`).
#[derive(Drop)]
pub struct Boolean {
    pub value: u8,
}

#[generate_trait]
pub impl BooleanImpl of BooleanTrait {
    /// Return the `bool` value from this object.
    #[inline]
    const fn bool(self: @Boolean) -> bool {
        *self.value != 0
    }
}

pub impl AnyTryIntoBoolean of Into<Any, Result<Boolean, Error>> {
    fn into(self: Any) -> Result<Boolean, Error> {
        self.tag().assert_eq(BooleanTagged::TAG)?;
        // X.690 section 8.2.1:
        // The encoding of a boolean value shall be primitive. The contents octets shall consist of
        // a single octet
        if self.header.length != Length::Definite(1) {
            return Result::Err(Error::InvalidLength);
        }
        let value = *self.data.get(0).unwrap().unbox();
        Ok(Boolean { value })
    }
}

pub impl BooleanCheckDerConstraints of CheckDerConstraints<Boolean> {
    fn check_constraints(any: @Any) -> Result<(), Error> {
        let c = any.data[0];
        // X.690 section 11.1
        if !(c == @0 || c == @0xff) {
            return Result::Err(Error::DerConstraintFailed(DerConstraint::InvalidBoolean));
        }
        Ok(())
    }
}

pub impl BooleanTagged of Tagged<Boolean> {
    const TAG: Tag = TAG_BOOLEAN;
}

pub impl BoolTagged of Tagged<bool> {
    const TAG: Tag = TAG_BOOLEAN;
}
