use crate::utils::extend_targets_to_power_of_two;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

pub(crate) fn add_merkle_root_target<const D: usize, F, H>(
    circuit_builder: &mut CircuitBuilder<F, D>,
    targets: Vec<Vec<Target>>,
    to_extend_target: Target,
) -> HashOutTarget
where
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    // extend `targets` to a length of power of two vector
    let targets = extend_targets_to_power_of_two(circuit_builder, targets, to_extend_target);
    // build the merkle tree root target
    let merkle_tree_height = targets.len().ilog2();
    let mut tree_hash_targets = vec![];
    for i in 0..targets.len() {
        let hash_target = circuit_builder.hash_or_noop::<H>(targets[i].clone());
        tree_hash_targets.push(hash_target);
    }
    let mut current_tree_height_index = 0;
    let mut i = 0;
    for height in 0..merkle_tree_height {
        // TODO: do we want to loop over all the height, or until cap(1) ?
        while i < current_tree_height_index + (1 << (merkle_tree_height - height)) {
            let hash_targets = circuit_builder.hash_n_to_hash_no_pad::<H>(
                [
                    tree_hash_targets[i as usize].elements.clone(),
                    tree_hash_targets[i as usize + 1].elements.clone(),
                ]
                .concat(),
            );
            tree_hash_targets.push(hash_targets);
            i += 2;
        }
        current_tree_height_index += 1 << (merkle_tree_height - height);
    }
    *tree_hash_targets.last().unwrap()
}
