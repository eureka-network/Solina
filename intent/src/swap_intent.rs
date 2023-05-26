use crate::{
    intent::{ExecuteRuntime, Intent},
    structured_hash::StructuredHashInterface,
};
use conversions::types::{Message, PrivateKey, Signature};
use keccak_hash::keccak;
use num_bigint::BigUint;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum SwapDirection {
    Buy,
    Sell,
}

/// Inputs for a swap
#[derive(Clone, Debug)]
pub struct SwapInputs {
    /// address
    from: BigUint,
    /// quote token
    quote_token: BigUint,
    /// base token
    base_token: BigUint,
    /// quote amount
    quote_amount: BigUint,
    /// trade direction
    direction: SwapDirection,
}

impl StructuredHashInterface for SwapInputs {
    fn type_encode() -> String {
        "SwapInputs(BigUint from,BigUint quote_token,BigUint base_token,BigUint quote_amount)"
            .to_string()
    }
    fn data_encode(&self) -> Vec<u8> {
        let from_hash = keccak(&self.from.to_bytes_be()).to_fixed_bytes();
        let quote_token_hash = keccak(&self.quote_token.to_bytes_be()).to_fixed_bytes();
        let base_token_hash = keccak(&self.base_token.to_bytes_be()).to_fixed_bytes();
        let quote_amount_hash = keccak(&self.quote_amount.to_bytes_be()).to_fixed_bytes();
        let direction = keccak(&[self.direction as u8]).to_fixed_bytes();

        [
            from_hash,
            quote_token_hash,
            base_token_hash,
            quote_amount_hash,
            direction,
        ]
        .concat()
    }
}

/// Constraints for a swap
#[derive(Clone, Debug)]
pub struct SwapConstraints {
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
    pub inputs: SwapInputs,
    pub constraints: SwapConstraints,
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

    fn sign_intent(&self, private_key: PrivateKey) -> Signature {
        let message = <Self as StructuredHashInterface>::structured_hash(&self);
        let message = Message::new_message(message);
        Signature::sign_message(&private_key, &message)
    }
}

impl StructuredHashInterface for SwapIntent {
    fn type_encode() -> String {
        let input_type_encoding = SwapInputs::type_encode();
        let constraints_type_encoding = SwapConstraints::type_encode();
        format!(
            "SwapIntent(SwapInputs inputs,SwapConstraints constraints){}{}",
            constraints_type_encoding, input_type_encoding
        )
    }

    fn data_encode(&self) -> Vec<u8> {
        let input_data_encoding = self.inputs.structured_hash();
        let constraints_data_encoding = self.constraints.structured_hash();
        [input_data_encoding, constraints_data_encoding].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works_swap_inputs_type_encoding() {
        assert_eq!(
            SwapInputs::type_encode().as_str(),
            "SwapInputs(BigUint from,BigUint quote_token,BigUint base_token,BigUint quote_amount)"
        );
    }

    #[test]
    fn it_works_swap_constraints_type_encoding() {
        assert_eq!(
            SwapConstraints::type_encode().as_str(),
            "SwapConstraints(BigUint min_base_token_amount)"
        );
    }

    #[test]
    fn it_works_swap_intent_type_encoding() {
        assert_eq!(
            SwapIntent::type_encode(),
            format!(
                "SwapIntent(SwapInputs inputs,SwapConstraints constraints){}{}",
                SwapConstraints::type_encode(),
                SwapInputs::type_encode(),
            )
        );
    }

    #[test]
    fn it_works_swap_inputs_struct_hash() {
        let inputs = SwapInputs {
            from: BigUint::from(255_u8),
            quote_amount: BigUint::from(1_000_000_000_000_u64),
            quote_token: BigUint::from(125_u8),
            base_token: BigUint::from(64_u8),
            direction: SwapDirection::Buy,
        };

        let hash = inputs.structured_hash();
        assert_eq!(
            hash,
            [
                186, 101, 125, 97, 49, 232, 81, 6, 161, 29, 40, 233, 194, 228, 236, 187, 13, 240,
                22, 165, 28, 19, 253, 103, 191, 74, 123, 112, 246, 125, 183, 139
            ]
        );
    }

    #[test]
    fn it_works_swap_constraints_struct_hash() {
        let constraints = SwapConstraints {
            min_base_token_amount: BigUint::from(64_u8),
        };

        let hash = constraints.structured_hash();
        assert_eq!(
            hash,
            [
                234, 72, 17, 64, 171, 119, 130, 160, 214, 239, 34, 138, 193, 55, 126, 70, 99, 51,
                17, 186, 102, 158, 246, 83, 37, 222, 43, 39, 99, 185, 141, 28
            ]
        );
    }

    #[test]
    fn it_works_swap_intent_struct_hash() {
        let intent = SwapIntent {
            inputs: SwapInputs {
                from: BigUint::from(255_u8),
                quote_amount: BigUint::from(1_000_000_000_000_u64),
                quote_token: BigUint::from(125_u8),
                base_token: BigUint::from(64_u8),
                direction: SwapDirection::Buy,
            },
            constraints: SwapConstraints {
                min_base_token_amount: BigUint::from(64_u8),
            },
        };

        let hash = intent.structured_hash();
        assert_eq!(
            hash,
            [
                189, 82, 148, 152, 172, 104, 0, 13, 64, 1, 22, 117, 178, 200, 200, 168, 243, 142,
                13, 152, 208, 63, 125, 179, 210, 98, 124, 23, 39, 58, 92, 19
            ]
        );
    }
}
