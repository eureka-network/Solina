use plonky2::field::{goldilocks_field::GoldilocksField, secp256k1_scalar::Secp256K1Scalar};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

pub mod circuit;
pub mod error;
pub mod signature_proof;
pub mod wallet;
pub mod witness;

pub const D: usize = 2;

pub(crate) type C = Secp256K1;
pub type F = GoldilocksField;
pub type FF = Secp256K1Scalar;
