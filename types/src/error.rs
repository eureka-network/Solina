use libsecp256k1::Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TypeConversionError {
    #[error("Invalid libsecp256k1 invalid type conversion: {0}")]
    InvalidLibSecp256K1TypeConversion(#[from] Error),
    #[error("Invalid slice length, current length is {0}, but it should be {1}")]
    InvalidSliceLength(usize, usize),
}
