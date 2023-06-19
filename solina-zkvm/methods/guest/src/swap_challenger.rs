use crate::swap_intent::SwapIntent;
use solina::{challenger::ChallengeOrganizer, intent::Intent, solver::Solver};

pub type PublicKey = [u8; 32];
pub type SwapScore = u64;

pub struct SwapSolution {}

pub struct SwapChallengeOrganizer {}

impl ChallengeOrganizer<PublicKey, SwapIntent> for SwapChallengeOrganizer {
    type Score = SwapScore;
    type Solution = SwapSolution;

    fn verify_solution(
        &self,
        solver_addr: PublicKey,
        solution: Self::Solution,
    ) -> Result<(), anyhow::Error> {
        todo!()
    }

    fn propose_batch_intent(&self) -> Vec<SwapIntent> {
        todo!()
    }

    fn compute_solution_score(&self, solution: Self::Solution) -> Self::Score {
        todo!()
    }
}
