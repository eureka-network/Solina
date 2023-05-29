use plonky2::plonk::{circuit_builder::CircuitBuilder, config::GenericConfig};

use crate::{
    intent::{Intent, SignatureProofData},
    D, F,
};

pub trait Solver<T>
where
    T: Intent,
{
    type Output;

    fn execute_runtime(&self, intents: Vec<T>) -> Self::Output;
    fn generate_execute_proof<C: GenericConfig<D, F = F>>(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        intents: Vec<(T, SignatureProofData<C>)>,
    ) -> Result<(), anyhow::Error>;
    fn verify_intents_signatures(&self, intents: Vec<T>) -> Result<(), anyhow::Error>;
}
