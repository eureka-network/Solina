use crate::{
    intent::{ExecuteRuntime, Intent},
    structured_hash::StructuredHashInterface,
};
use keccak_hash::keccak;
use num_bigint::BigUint;
use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::Field};
use plonky2_ecdsa::curve::{
    ecdsa::{sign_message, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
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

impl StructuredHashInterface for SwapInputs {
    fn type_encode() -> String {
        "SwapInputs(BigUint from, BigUint quote_token, BigUint base_token, BigUint quote_amount)"
            .to_string()
    }
    fn data_encode(&self) -> Vec<u8> {
        let from_hash = keccak(&self.from.to_bytes_be()).to_fixed_bytes();
        let quote_token_hash = keccak(&self.quote_token.to_bytes_be()).to_fixed_bytes();
        let base_token_hash = keccak(&self.base_token.to_bytes_be()).to_fixed_bytes();
        let quote_amount_hash = keccak(&self.quote_amount.to_bytes_be()).to_fixed_bytes();

        [
            from_hash,
            quote_token_hash,
            base_token_hash,
            quote_amount_hash,
        ]
        .concat()
    }
}

/// Constraints for a swap
#[derive(Clone, Debug)]
pub(crate) struct SwapConstraints {
    /// max slippage amount
    min_base_token_amount: BigUint,
}

impl StructuredHashInterface for SwapConstraints {
    fn type_encode() -> String {
        "SwapConstraints(BigUint min_base_token_amount)".to_string()
    }
    fn data_encode(&self) -> Vec<u8> {
        keccak(&self.min_base_token_amount.to_bytes_be())
            .as_fixed_bytes()
            .to_vec()
    }
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
        let message = <Self as StructuredHashInterface>::structured_hash(&self);
        let message = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(&message));
        sign_message(message, private_key)
    }
}

impl StructuredHashInterface for SwapIntent {
    fn type_encode() -> String {
        let input_type_encoding = SwapInputs::type_encode();
        let constraints_type_encoding = SwapInputs::type_encode();
        format!(
            "SwapIntent(SwapInputs inputs, SwapConstraints constraints){}{}",
            constraints_type_encoding, input_type_encoding
        )
    }

    fn data_encode(&self) -> Vec<u8> {
        let input_data_encoding = self.inputs.structured_hash();
        let constraints_data_encoding = self.constraints.structured_hash();
        [input_data_encoding, constraints_data_encoding].concat()
    }
}
