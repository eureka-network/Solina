#[cfg(test)]
use crate::Provable;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::RichField, merkle_proofs, merkle_tree::MerkleTree, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;
type H = PoseidonHash;

pub(crate) fn extend_to_power_of_two<F: RichField + Extendable<D>, const D: usize>(
    mut values: Vec<Vec<F>>,
    to_extend_value: F,
) -> Vec<Vec<F>> {
    let log_2_len = values.len().ilog2();
    if 2_u64.pow(log_2_len) == values.len() as u64 {
        return values;
    }
    let diff = 2_u64.pow(log_2_len + 1) - values.len() as u64 - 1;

    // append length of `values`
    values.push(vec![F::from_canonical_u64(values.len() as u64)]);
    // trivially extend the vector until we obtain a power 2 length output vector
    let to_extend_values = vec![vec![to_extend_value]; diff as usize];
    values.extend(to_extend_values);
    values
}

#[test]
fn tree_generation() {
    let f_zero: F = F::ZERO;
    let f_one: F = F::ONE;
    let f_two: F = F::from_canonical_u64(2);
    let f_three: F = F::from_canonical_u64(3);

    let config = CircuitConfig::standard_recursion_config();
    let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

    let merkle_tree_leaves = vec![vec![f_zero], vec![f_one], vec![f_two], vec![f_three]];
    let merkle_tree = MerkleTree::<F, H>::new(merkle_tree_leaves.clone(), 0);

    let mut merkle_tree_leaf_targets = Vec::with_capacity(4);
    (0..4).for_each(|_| merkle_tree_leaf_targets.push(vec![circuit_builder.add_virtual_target()]));
    let (merkle_targets, merkle_root_hash_target) = merkle_tree.compile(&mut circuit_builder);

    let mut partial_witness = PartialWitness::<F>::new();
    <MerkleTree<F, H> as Provable<F, D>>::fill(
        &merkle_tree,
        &mut partial_witness,
        merkle_targets,
        merkle_root_hash_target,
    )
    .unwrap();

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data.prove(partial_witness).unwrap();

    assert!(circuit_data.verify(proof_with_pis).is_ok());
}

#[test]
fn tree_generation_2() {
    let f_zero: F = F::ZERO;
    let f_one: F = F::ONE;
    let f_two: F = F::from_canonical_u64(2);
    let f_three: F = F::from_canonical_u64(3);
    let f_four: F = F::from_canonical_u64(4);

    let config = CircuitConfig::standard_recursion_config();
    let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

    let merkle_tree_leaves = vec![
        vec![f_zero],
        vec![f_one],
        vec![f_two],
        vec![f_three],
        vec![f_four],
    ];
    let merkle_tree_leaves = extend_to_power_of_two::<F, D>(merkle_tree_leaves, F::ZERO);
    let merkle_tree = MerkleTree::<F, H>::new(merkle_tree_leaves.clone(), 0);

    let mut merkle_tree_leaf_targets = Vec::with_capacity(5);
    (0..5).for_each(|_| merkle_tree_leaf_targets.push(vec![circuit_builder.add_virtual_target()]));
    let (merkle_targets, merkle_root_hash_target) = merkle_tree.compile(&mut circuit_builder);

    let mut partial_witness = PartialWitness::<F>::new();
    <MerkleTree<F, H> as Provable<F, D>>::fill(
        &merkle_tree,
        &mut partial_witness,
        merkle_targets,
        merkle_root_hash_target,
    )
    .unwrap();

    let circuit_data = circuit_builder.build::<C>();
    let proof_with_pis = circuit_data.prove(partial_witness).unwrap();

    assert!(circuit_data.verify(proof_with_pis).is_ok());
}
