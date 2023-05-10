use plonky2_ecdsa::gadgets::{ecdsa::ECDSASignatureTarget, biguint::BigUintTarget};
use crate::{FF, StructuredHash};

pub trait Intent {
    fn structured_hash(&self) -> StructuredHash;
    fn sign_intent(&self, private_key: BigUintTarget) -> ECDSASignatureTarget<FF>;
}
