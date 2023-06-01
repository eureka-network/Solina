use anyhow::anyhow;
use binary_search_tree::BinarySearchTree;
use merkle_tree::tree_circuit_generation::MerkleRootGenerationBuilder;
use plonky2::{
    hash::{merkle_tree::MerkleCap, poseidon::PoseidonHash},
    iop::target::BoolTarget,
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;

use crate::{
    circuit::ECDSAIntentCircuit,
    solver::{IntentSignature, ProofVerifyData, Solver, SolverCircuitGenerator},
    swap_intent::SwapIntent,
    D, F,
};

/// Struct encapsulating swap intents. Currently, ordering of intents is kept by ordering
/// both buy and sell orders. One could optimize this, using balanced binary trees,
pub struct SwapState {
    /// Queue of stored intents, for buying orders. This could be stored in a distribued data structured,
    /// but for now, we assume that each solver contains its own (local) queue. We further
    /// assume that this data structure is ordered, with descending price order, in a binary tree.
    buy_order_intents: BinarySearchTree<SwapIntent>,
    /// Queue of stored intents, for selling orders. This could be stored in a distribued data structured,
    /// but for now, we assume that each solver contains its own (local) queue. We further
    /// assume that this data structure is ordered, with ascending price order, in a binary tree.
    sell_order_intents: BinarySearchTree<SwapIntent>,
}

/// Swap state commitments, for buy and sell intents, simultaneously.
pub struct SwapStateCommitment {
    /// Commitment to buy intents ordered vec
    buy_intent_commitment: MerkleCap<F, PoseidonHash>,
    /// Commitment to sell intents ordered vec
    sell_intent_commitment: MerkleCap<F, PoseidonHash>,
}

pub struct SwapSolver;

impl Solver<SwapIntent> for SwapSolver {
    type State = SwapState;
    type StateCommitment = SwapStateCommitment;

    fn commit_to_current_state(&self) -> Self::StateCommitment {
        todo!()
    }

    fn current_state(&self) -> Self::State {
        todo!()
    }

    fn execute_on_new_intent(&mut self, intent: SwapIntent) -> Self::State {
        todo!()
    }

    fn generate_state_proof(&self, circuit_builder: &CircuitBuilder<F, D>) -> ProofVerifyData {
        todo!()
    }
}

pub struct SwapSolverCircuitGenerator {
    recursive_proof_data: Option<ProofVerifyData>,
}

impl SwapSolverCircuitGenerator {
    pub fn new() -> SwapSolverCircuitGenerator {
        Self {
            recursive_proof_data: None,
        }
    }

    pub(crate) fn new_with_recursive_proof_data(recursive_proof_data: ProofVerifyData) -> Self {
        Self {
            recursive_proof_data: Some(recursive_proof_data),
        }
    }
}

impl SolverCircuitGenerator<SwapIntent> for SwapSolverCircuitGenerator {
    fn generate_circuit(self, solver: impl Solver<SwapIntent>, intent: SwapIntent) -> Self {
        todo!()
    }
}

pub struct SwapSolverRuntimeExec {
    circuit_builder: CircuitBuilder<F, D>,
}

impl SwapSolverRuntimeExec {
    fn generate_current_execution_state_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        intents: Vec<IntentSignature<SwapIntent>>,
    ) -> Result<ProofVerifyData, anyhow::Error> {
        if intents.is_empty() {
            return Err(anyhow!("Cannot generate a proof on an empty intent vector"));
        }
        // 1. Generate targets for Poseidon hashes of (keccak structured hash) intents
        let intent_hashes = circuit_builder.add_virtual_hashes(intents.len());

        // 2. Set the above [`HashOutTarget`]'s as public inputs
        intent_hashes
            .iter()
            .for_each(|t| circuit_builder.register_public_inputs(&t.elements));

        // 3. Generate a Merkle tree for [`HashOutTarget`] in 1.

        // 4. Generate a proof that these intents are well sorted
        let swap_intents_data = intents
            .iter()
            .map(|i| {
                // 4.1 Add targets for price
                // TODO: verify that the number of limbs in a [`BigUint`] can be generated in this way ([`BigUint`] either uses [`u64`] or [`u32`] depending on the CPUs arch)
                let price_biguint_target = circuit_builder
                    .add_virtual_biguint_target(i.intent.get_price().to_u32_digits().len());
                // 4.2 Add targets for base token intents amount
                let base_amount_biguint_target = circuit_builder.add_virtual_biguint_target(
                    i.intent
                        .constraints
                        .min_base_token_amount
                        .to_u32_digits()
                        .len(),
                );
                (price_biguint_target, base_amount_biguint_target)
            })
            .collect::<Vec<_>>();

        // 4.3. Assert ordering depending on swap direction
        let intent_swap_direction = circuit_builder
            .constant_bool(intents.first().unwrap().intent.inputs.direction.as_bool());
        // 4.3.1. Assert that all direction targets are equal
        (1..intents.len()).for_each(|i| {
            let _target =
                circuit_builder.constant_bool(intents[i].intent.inputs.direction.as_bool());
            circuit_builder.connect(intent_swap_direction.target, _target.target);
        });
        // for ease of logic, we consider the negation of `intent_swap_direction`
        let not_intent_swap_direction = circuit_builder.not(intent_swap_direction);

        let n = swap_intents_data.len();
        let mut prev_element = swap_intents_data.first().unwrap();
        let bool_target = circuit_builder._true();

        (1..n).for_each(|i| {
            let cur_element = &swap_intents_data[i];
            let price_cmp = circuit_builder.cmp_biguint(&prev_element.0, &cur_element.0);
            let base_amount_cmp = circuit_builder.cmp_biguint(&prev_element.1, &cur_element.1);
            let not_base_amount_cmp = circuit_builder.not(base_amount_cmp);

            let true_target = circuit_builder._true();
            let false_target = circuit_builder._false();

            let buy_if_cmp =
                circuit_builder._if(price_cmp, true_target.target, base_amount_cmp.target);
            let sell_if_cmp =
                circuit_builder._if(price_cmp, false_target.target, not_base_amount_cmp.target);

            let bool_order_target = BoolTarget::new_unsafe(circuit_builder._if(
                not_intent_swap_direction,
                buy_if_cmp,
                sell_if_cmp,
            ));
            circuit_builder.assert_bool(bool_order_target);
        });

        // 5. We don't need to verify signature proofs, this only needs to be done at each state transition

        // 6. Create a Merkle tree from the hashes in 1.

        todo!();
    }

    fn generate_execute_state_transition_circuit(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        previous_state_proof: ProofVerifyData,
        new_intent: IntentSignature<SwapIntent>,
        state_intents: Vec<IntentSignature<SwapIntent>>,
    ) {
        // 1. Verify intent signature, for new intent
        let ecdsa_targets = circuit_builder.verify_intent_signature();

        // 2. Verify previous state proof
        let ProofVerifyData {
            proof_with_pis,
            inner_verifier_data,
            inner_common_data,
        } = previous_state_proof;
        circuit_builder.verify_proof::<PoseidonGoldilocksConfig>(
            &proof_with_pis,
            &inner_verifier_data,
            &inner_common_data,
        );

        // 3. Build Merkle Tree

        todo!();
    }
}
