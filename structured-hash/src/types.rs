use hex::FromHex;
use std::str::FromStr;

pub(crate) type Address = [u8; 32];
pub(crate) type Salt = [u8; 32];
pub(crate) type StructuredHash = [u8; 32];
pub(crate) type EncodedValue = [u8; 32];
