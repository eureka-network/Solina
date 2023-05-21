use crate::StructuredHash;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::curve::{
    ecdsa::{ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};

/// Reference enum from a label to the actual
/// computation execution, and a proof generation
pub(crate) enum ExecuteRuntime {
    Swap,
}

pub(crate) trait Intent {
    type Inputs;
    type Constraints;

    fn build_intent(
        inputs: Self::Inputs,
        constraints: Self::Constraints,
        execute_runtime: ExecuteRuntime,
    ) -> Self;
    fn structured_hash(&self) -> StructuredHash;
    fn sign_intent(&self, private_key: ECDSASecretKey<Secp256K1>) -> ECDSASignature<Secp256K1>;
    fn get_constraints(&self) -> Self::Constraints;
    fn get_inputs(&self) -> Self::Inputs;
    fn get_runtime_execution(&self) -> ExecuteRuntime;
}
