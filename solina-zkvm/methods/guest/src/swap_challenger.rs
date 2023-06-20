// use crate::{swap_intent::SwapIntent, Amount, PublicKey};
// use anyhow::anyhow;
// use solina::{challenger::ChallengeOrganizer, intent::Intent, solver::Solver};

// pub type SwapScore = u64;

// pub struct SwapRow {
//     pub(crate) addr: PublicKey,
//     pub(crate) amount_in: Amount,
//     pub(crate) amount_out: Amount,
// }

// impl SwapRow {
//     pub fn new(addr: PublicKey, amount_in: Amount, amount_out: Amount) -> Self {
//         Self {
//             addr,
//             amount_in,
//             amount_out,
//         }
//     }

//     pub fn get_amount_in(&self) -> Amount {
//         self.amount_in
//     }

//     pub fn get_amount_out(&self) -> Amount {
//         self.amount_out
//     }

//     pub fn get_address(&self) -> PublicKey {
//         self.addr
//     }
// }

// pub struct SwapTable {
//     pub(crate) rows: Vec<SwapRow>,
// }

// impl SwapTable {
//     pub fn new(rows: Vec<SwapRow>) -> Self {
//         Self { rows }
//     }

//     pub fn get_rows(&self) -> Vec<&SwapRow> {
//         self.rows.iter().collect()
//     }

//     pub fn get_row_for_address(&self, addr: PublicKey) -> Option<&SwapRow> {
//         let rows = self
//             .rows
//             .iter()
//             .filter(|x| x.addr == addr)
//             .collect::<Vec<_>>();
//         rows.first().copied()
//     }
// }

// pub struct SwapSolution {
//     pub table: SwapTable,
// }

// pub struct SwapChallengeOrganizer {
//     solver_registry: Vec<PublicKey>,
// }

// impl SwapChallengeOrganizer {
//     pub fn new() -> Self {
//         Self {
//             solver_registry: vec![],
//         }
//     }

//     pub fn add_solver_to_registry(&mut self, solver_address: PublicKey) {
//         self.solver_registry.push(solver_address);
//     }
// }

// impl ChallengeOrganizer<PublicKey, SwapIntent> for SwapChallengeOrganizer {
//     type Score = SwapScore;
//     type Solution = SwapSolution;

//     fn verify_solution(
//         &self,
//         solver_address: PublicKey,
//         solution: Self::Solution,
//     ) -> Result<(), anyhow::Error> {
//         // no solver should publish more than once a solution
//         if self.solver_registry.contains(&solver_address) {
//             return Err(anyhow!(
//                 "Solver registry already contains solver's public key",
//             ));
//         }

//         let table = solution.table;
//         for row in table.rows.iter() {}

//         Ok(())
//     }

//     fn propose_batch_intent(&self) -> Vec<SwapIntent> {
//         todo!()
//     }

//     fn compute_solution_score(&self, solution: Self::Solution) -> Self::Score {
//         todo!()
//     }
// }
