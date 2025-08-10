pub use asn1::Tag;
use crate::ber::{BerObject, BerObjectContent};

mod multi;
mod parser;
mod tagged;
pub use crate::der::multi::*;
pub use crate::der::parser::*;
pub use crate::der::tagged::*;

/// Representation of a DER-encoded (X.690) object
///
/// Note that a DER object is just a BER object, with additional constraints.
pub type DerObject = BerObject;

/// BER object content
///
/// This is the same object as `BerObjectContent`.
pub type DerObjectContent = BerObjectContent;
