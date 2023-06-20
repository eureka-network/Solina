pub trait Intent {
    type Addr;
    type Inputs;
    type Constraints;

    fn build_intent(
        address: Self::Addr,
        inputs: Self::Inputs,
        constraints: Self::Constraints,
    ) -> Self;
    // fn sign_intent(&self, private_key: PrivateKey) -> Signature;
    fn get_constraints(&self) -> Self::Constraints;
    fn get_inputs(&self) -> Self::Inputs;
}
