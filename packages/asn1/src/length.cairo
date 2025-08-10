use crate::Error;

/// BER Object Length.
#[derive(Drop, Debug, Copy, PartialEq)]
pub enum Length {
    /// Definite form (X.690 8.1.3.3).
    Definite: usize,
    /// Indefinite form (X.690 8.1.3.6).
    Indefinite,
}

#[generate_trait]
pub impl LengthImpl of LengthTrait {
    /// Get length of primitive object
    #[inline]
    fn definite(self: @Length) -> Result<usize, Error> {
        match self {
            Length::Definite(sz) => Ok(*sz),
            Length::Indefinite => Err(Error::IndefiniteLengthUnexpected),
        }
    }

    /// Return error if length is not definite
    #[inline]
    const fn assert_definite(self: @Length) -> Result<(), Error> {
        match self {
            Length::Definite(_) => Ok(()),
            Length::Indefinite => Err(Error::IndefiniteLengthUnexpected),
        }
    }
}
