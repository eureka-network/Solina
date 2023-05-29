use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CommonCircuitData,
        circuit_data::{VerifierCircuitData, VerifierCircuitTarget},
        config::PoseidonGoldilocksConfig,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    intent::{Intent, SignatureProofData},
    D, F,
};

#[allow(dead_code)]
pub struct IntentSignature<T>
where
    T: Intent,
{
    pub intent: T,
    pub signature_proof_data: SignatureProofData<PoseidonGoldilocksConfig>,
}

pub trait Solver<T>
where
    T: Intent,
{
    type Output;

    fn queue_intent(&mut self, intent: T);
    fn execute_runtime(&self, intent: T, partial_witness: &mut PartialWitness<F>) -> Self::Output;
    fn generate_execute_proof(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        partial_witness: &mut PartialWitness<F>,
    ) -> Result<(), anyhow::Error>;
    fn verify_intents_signatures(&self, intents: Vec<T>) -> Result<(), anyhow::Error>;
}

pub struct ProofVerifyData {
    pub proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub inner_verifier_data: VerifierCircuitTarget,
    pub inner_common_data: CommonCircuitData<F, D>,
}

pub trait SolverRuntimeExec<T>
where
    T: Intent,
{
    fn generate_current_execution_state_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        state_intents: Vec<IntentSignature<T>>,
    ) -> Result<ProofVerifyData, anyhow::Error>;

    fn generate_execute_state_transition_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        previous_state_proof: ProofVerifyData,
        new_intent: IntentSignature<T>,
        state_intents: Vec<IntentSignature<T>>,
    );
}
