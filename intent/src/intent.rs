use conversions::types::{PrivateKey, Signature};

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
    fn sign_intent(&self, private_key: PrivateKey) -> Signature;
    fn get_constraints(&self) -> Self::Constraints;
    fn get_inputs(&self) -> Self::Inputs;
    fn get_runtime_execution(&self) -> ExecuteRuntime;
}
