use crate::intent::Intent;

// #[allow(dead_code)]
// pub struct IntentSignature<T, C>
// where
//     T: Intent,
//     C: GenericConfig<D, F = F>,
// {
//     intent: T,
//     signature_proof_data: SignatureProofData<C>,
// }

pub trait Solver<Int>
where
    Int: Intent,
{
    type Addr;
    type Solution;
    type SolutionTrace;

    fn publish_solution(&self) -> Self::Solution;
    fn publish_solution_trace(&self) -> Self::SolutionTrace;
    fn get_address(&self) -> Self::Addr;
}

pub trait ChallengeOrganizer<Addr, Int>
where
    Int: Intent,
{
    type Score;
    type Solution;

    fn verify_solution(
        &self,
        solver_addr: Addr,
        solution: Self::Solution,
    ) -> Result<(), anyhow::Error>;
    fn propose_batch_intent(&self) -> Vec<Int>;
    fn compute_solution_score(&self, solution: Self::Solution) -> Self::Score;
}
