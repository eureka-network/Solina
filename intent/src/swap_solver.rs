use anyhow::anyhow;
use binary_search_tree::BinarySearchTree;
use merkle_tree::tree_circuit_generation::MerkleRootGenerationBuilder;
use plonky2::{
    hash::{merkle_tree::MerkleCap, poseidon::PoseidonHash},
    iop::target::BoolTarget,
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use plonky2_ecdsa::gadgets::biguint::{CircuitBuilderBiguint, BigUintTarget};

use crate::{
    circuit::ECDSAIntentCircuit,
    solver::{IntentSignature, ProofVerifyData, Solver, SolverCircuitGenerator},
    swap_intent::{SwapIntent, Price},
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

fn generate_state_transition_circuit(
    circuit_builder: &mut CircuitBuilder<F, D>,
    previous_state_proof: ProofVerifyData,
    new_intent: IntentSignature<SwapIntent>,
    state_intents: Vec<IntentSignature<SwapIntent>>,
) -> Result<(), anyhow::Error> {
    if state_intents.is_empty() {
        generate_initial_state_circuit(circuit_builder, new_intent)?;
    }

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

    // 3. Generate targets for each of the keccak structured hashes, for each intent in the state
    //    and register these as public inputs
    let keccak_structured_hash_intent_targets = state_intents
        .iter()
        .map(|i| circuit_builder.add_virtual_target_arr::<32>())
        .collect::<Vec<_>>();
    keccak_structured_hash_intent_targets
        .iter()
        .for_each(|ts| circuit_builder.register_public_inputs(ts));

    // 4. Build Merkle Tree from the previous keccak structured hash targets
    let to_extend_target = circuit_builder.zero();
    let root_targets = <CircuitBuilder<F, D> as MerkleRootGenerationBuilder<D, F, PoseidonHash>>::add_merkle_root_target(
        circuit_builder, 
        keccak_structured_hash_intent_targets
            .iter()
            .map(|v| v.to_vec())
            .collect::<Vec<_>>(),
        to_extend_target,
    );

    // 5. Register Merkle tree root targets as public inputs
    let public_input_root_targets = circuit_builder.add_virtual_hash();
    circuit_builder.register_public_inputs(&public_input_root_targets.elements);

    // 6. Connects both `root_targets` and `public_input_root_targets`
    root_targets
        .elements
        .iter()
        .zip(public_input_root_targets.elements)
        .for_each(|(t1, t2)| circuit_builder.connect(*t1, t2));

    // 7. Generate a proof that these intents are well sorted
    // TODO: for now, we assume that our solver only receives intents for a single token pair (A, B),
    // so we don't need to worry about enforcing pair satisfiability
    let targets = generate_intent_correct_ordering_proof(circuit_builder, state_intents)?;

    Ok(())
}

fn generate_initial_state_circuit(
    circuit_builder: &mut CircuitBuilder<F, D>,
    new_intent: IntentSignature<SwapIntent>,
) -> Result<(), anyhow::Error> {
    Ok(())
}

pub(crate) struct PriceAndBaseAmountTargets {
    price_targets: Vec<BigUintTarget>,
    base_amount_targets: Vec<BigUintTarget>,
}

fn generate_intent_correct_ordering_proof(
    circuit_builder: &mut CircuitBuilder<F, D>,
    state_intents: Vec<IntentSignature<SwapIntent>>,
) -> Result<PriceAndBaseAmountTargets, anyhow::Error> {
    if state_intents.is_empty() {
        return Err(anyhow!(
            "There is no non-trivial ordering for an empty vector of intents"
        ));
    }
    // 1. Adds price and base amount token targets
    let price_data_biguint_targets = state_intents
        .iter()
        .map(|i| {
            // 1.1 Add targets for price
            // TODO: verify that the number of limbs in a [`BigUint`] can be generated in this way ([`BigUint`] either uses [`u64`] or [`u32`] depending on the CPUs arch)
            circuit_builder
                .add_virtual_biguint_target(i.intent.get_price().to_u32_digits().len())
            
        })
        .collect::<Vec<_>>();

    let base_amount_data_biguint_targets = state_intents.iter().map(|i|  
        // 1.2 Add targets for base token intents amount
        circuit_builder.add_virtual_biguint_target(
            i.intent
                .constraints
                .min_base_token_amount
                .to_u32_digits()
                .len(),
        )).collect::<Vec<_>>(); 

    // 2. Assert ordering depending on swap direction
    let intent_swap_direction = circuit_builder.constant_bool(
        state_intents
            .first()
            .unwrap()
            .intent
            .inputs
            .direction
            .as_bool(),
    );
    // 3. Assert that all direction targets are equal
    (1..state_intents.len()).for_each(|i| {
        let _target =
            circuit_builder.constant_bool(state_intents[i].intent.inputs.direction.as_bool());
        circuit_builder.connect(intent_swap_direction.target, _target.target);
    });

    // for ease of logic, we consider the negation of `intent_swap_direction`
    let not_intent_swap_direction = circuit_builder.not(intent_swap_direction);

    // 4. Assert that set of state intents is well ordered
    let n = price_data_biguint_targets.len();
    let mut prev_price_element = price_data_biguint_targets.first().unwrap();
    let mut prev_base_amount_element = base_amount_data_biguint_targets.first().unwrap();
    let true_target = circuit_builder._true();
    let false_target = circuit_builder._false();

    (1..n).for_each(|i| {
        let cur_price_element = &price_data_biguint_targets[i];
        let cur_base_amount_element = &base_amount_data_biguint_targets[i];
        let price_cmp = circuit_builder.cmp_biguint(&prev_price_element, &cur_price_element);
        let base_amount_cmp = circuit_builder.cmp_biguint(&prev_base_amount_element, &cur_base_amount_element);
        let not_base_amount_cmp = circuit_builder.not(base_amount_cmp);

        // The ordering we enforce here is as follows:
        // If the order is a buy order, then we enforce that intents I1 <= I2
        // if p1 > p2 or ((p1 = p2) and (b1 <= b2)).
        let buy_if_cmp =
            circuit_builder._if(price_cmp, false_target.target, base_amount_cmp.target);
        // Otherwise, if we are in the case of a sell order, then I1 <= I2
        // if p1 < p2 or ((p1 = p2) and (b1 >= b2))
        let sell_if_cmp =
            circuit_builder._if(price_cmp, true_target.target, not_base_amount_cmp.target);

        let bool_order_target = BoolTarget::new_unsafe(circuit_builder._if(
            not_intent_swap_direction, // false <-> buy, true <-> sell
            buy_if_cmp,
            sell_if_cmp,
        ));
        // assert constraints
        circuit_builder.assert_bool(bool_order_target);

        // update prev price and base amounts elements
        prev_price_element = cur_price_element;
        prev_base_amount_element = cur_base_amount_element;

        });

    Ok(PriceAndBaseAmountTargets { 
        price_targets: price_data_biguint_targets, 
        base_amount_targets: base_amount_data_biguint_targets
    })
}
