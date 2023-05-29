use plonky2::field::{goldilocks_field::GoldilocksField, secp256k1_scalar::Secp256K1Scalar};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

pub mod circuit;
mod intent;
pub mod solver;
pub mod structured_hash;
mod swap_intent;
pub mod witness;

pub const D: usize = 2;

pub(crate) type C = Secp256K1;
pub type F = GoldilocksField;
pub type FF = Secp256K1Scalar;
#[allow(dead_code)]
pub(crate) type StructuredHash = [u8; 32];
