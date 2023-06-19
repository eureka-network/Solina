use crate::intent::Intent;

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
