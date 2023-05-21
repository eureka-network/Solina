use crate::{
    intent::{ExecuteRuntime, Intent},
    StructuredHash,
};
use num_bigint::BigUint;
use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::Field};
use plonky2_ecdsa::{
    curve::{
        ecdsa::{sign_message, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
    gadgets::biguint::BigUintTarget,
};

/// Inputs for a swap
#[derive(Clone, Debug)]
pub(crate) struct SwapInputs {
    /// address
    from: BigUint,
    /// quote token
    quote_token: BigUint,
    /// base token
    base_token: BigUint,
    /// quote amount
    quote_amount: BigUint,
}

/// Constraints for a swap
#[derive(Clone, Debug)]
pub(crate) struct SwapConstraints {
    /// max slippage amount
    min_base_token_amount: BigUint,
}

/// Intent to swap tokens
/// todo[ben]: this is incomplete, but let's focus on the pathways first
#[allow(dead_code)]
pub struct SwapIntent {
    inputs: SwapInputs,
    constraints: SwapConstraints,
}

impl Intent for SwapIntent {
    type Inputs = SwapInputs;
    type Constraints = SwapConstraints;

    fn build_intent(
        inputs: Self::Inputs,
        constraints: Self::Constraints,
        _execute_runtime: crate::intent::ExecuteRuntime,
    ) -> Self {
        Self {
            inputs,
            constraints,
        }
    }

    fn get_constraints(&self) -> Self::Constraints {
        self.constraints.clone()
    }

    fn get_inputs(&self) -> Self::Inputs {
        self.inputs.clone()
    }

    fn get_runtime_execution(&self) -> ExecuteRuntime {
        ExecuteRuntime::Swap
    }

    fn sign_intent(&self, private_key: ECDSASecretKey<Secp256K1>) -> ECDSASignature<Secp256K1> {
        let message = self.structured_hash();
        let message = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(&message));
        sign_message(message, private_key)
    }

    fn structured_hash(&self) -> StructuredHash {}
}
