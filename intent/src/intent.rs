use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
        config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
};
use types::types::{Message, PrivateKey, PublicKey, Signature};

use crate::{
    circuit::ECDSAIntentCircuit, structured_hash::StructuredHashInterface,
    witness::ECDSAIntentWitness, D, F,
};

/// Reference enum from a label to the actual
/// computation execution, and a proof generation
pub enum ExecuteRuntime {
    Swap,
}

pub trait Intent {
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

#[allow(dead_code)]
pub struct SignatureProofData<C: GenericConfig<D, F = F>> {
    pub proof_with_pis: ProofWithPublicInputs<F, C, D>,
    pub common: CommonCircuitData<F, D>,
    pub verifier_only: VerifierOnlyCircuitData<C, D>,
}

#[allow(dead_code)]
pub fn generate_intent_signature_proof<C, I>(
    intent: I,
    public_key: PublicKey,
    signature: Signature,
) -> Result<SignatureProofData<C>, anyhow::Error>
where
    C: GenericConfig<D, F = F>,
    I: StructuredHashInterface + Intent,
{
    let config = CircuitConfig::standard_ecc_config();
    let mut circuit_builder = CircuitBuilder::new(config);
    let mut partial_witness = PartialWitness::<F>::new();

    let signature_targets = circuit_builder.verify_intent_signature();
    let message = Message::from_slice(&intent.structured_hash())?;

    let message_conversion = message.into_plonky2_message();
    let public_key_conversion = public_key.into_plonky2_public_key();
    let signature_conversion = signature.into_plonky2_signature();

    partial_witness.verify_signed_intent(
        &mut circuit_builder,
        message_conversion,
        public_key_conversion,
        signature_conversion,
        signature_targets,
    );

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data.prove(partial_witness.clone())?;

    Ok(SignatureProofData {
        proof_with_pis,
        common: circuit_data.common,
        verifier_only: circuit_data.verifier_only,
    })
}
