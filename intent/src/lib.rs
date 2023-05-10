use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;

mod intent;
mod swap_intent;

pub(crate) type C = Secp256K1;
pub(crate) type FF = Secp256K1Scalar;
pub(crate) type StructuredHash = [u8; 32];
