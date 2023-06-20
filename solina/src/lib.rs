use plonky2::field::{goldilocks_field::GoldilocksField, secp256k1_scalar::Secp256K1Scalar};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

pub mod challenger;
pub mod intent;
pub mod solver;
pub mod structured_hash;
