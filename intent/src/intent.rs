use conversions::types::{Message, PrivateKey, Signature};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, config::GenericConfig, proof::ProofWithPublicInputs},
};

use crate::{
    circuit::ECDSAIntentCircuit, structured_hash::StructuredHashInterface,
    witness::ECDSAIntentWitness,
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
    fn sign_intent(&self, private_key: PrivateKey) -> Signature;
    fn get_constraints(&self) -> Self::Constraints;
    fn get_inputs(&self) -> Self::Inputs;
    fn get_runtime_execution(&self) -> ExecuteRuntime;
}

// fn generate_intent_signature_proof<F, C, I, const D: usize>(
//     circuit_builder: &mut CircuitBuilder<F, D>,
//     partial_witness: &mut PartialWitness<F>,
//     intent: I,
//     signature: Signature,
// ) -> ProofWithPublicInputs<F, C, D>
// where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D>,
//     I: StructuredHashInterface + Intent,
// {
//     let signature_targets = circuit_builder.verify_intent_signature();
//     // let message = Message::intent.structured_hash();

//     partial_witness.verify_signed_intent(circuit_builder);
// }
