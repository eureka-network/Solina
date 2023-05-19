use crate::{StructuredHash, C};
use num_bigint::BigUint;
use plonky2_ecdsa::curve::ecdsa::ECDSASignature;

pub(crate) trait Intent {
    fn structured_hash(&self) -> StructuredHash;
    // fn sign_intent(&self, private_key: BigUint) -> ECDSASignature<C>;
}
