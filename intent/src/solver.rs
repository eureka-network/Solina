use plonky2::plonk::{
    circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData,
    circuit_data::VerifierCircuitTarget, config::PoseidonGoldilocksConfig,
    proof::ProofWithPublicInputsTarget,
};

use crate::{
    intent::{Intent, SignatureProofData},
    D, F,
};

#[allow(dead_code)]
#[derive(Clone)]
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
    type State;
    type StateCommitment;

    fn current_state(&self) -> Self::State;
    fn execute_on_new_intent(&mut self, intent: T) -> Self::State;
    fn commit_to_current_state(&self) -> Self::StateCommitment;
    fn generate_state_proof(&self, circuit_builder: &CircuitBuilder<F, D>) -> ProofVerifyData;
}

pub trait SolverCircuitGenerator<T>
where
    T: Intent,
{
    fn generate_circuit(self, solver: impl Solver<T>, intent: T) -> Self;
}

pub struct ProofVerifyData {
    pub proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub inner_verifier_data: VerifierCircuitTarget,
    pub inner_common_data: CommonCircuitData<F, D>,
}
