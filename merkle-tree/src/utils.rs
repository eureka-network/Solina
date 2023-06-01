use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

/// Extends a given vector of `Target`s of a certain length len
/// to a power of 2 len vector of `Target`s. This is done, by
/// appending with a constant `Target` of the length with a fixed `to_exted_target` to the original vector,
pub fn extend_targets_to_power_of_two<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    mut targets: Vec<Vec<Target>>,
    to_extend_target: Target,
) -> Vec<Vec<Target>> {
    let log_2_len = targets.len().ilog2();
    if 2_u64.pow(log_2_len) == targets.len() as u64 {
        return targets;
    }
    let diff = 2_u64.pow(log_2_len + 1) - targets.len() as u64 - 1;

    // append length of `targets`
    targets.push(vec![
        builder.constant(F::from_canonical_u64(targets.len() as u64))
    ]);
    // trivially extend the vector until we obtain a power 2 length output vector
    let to_extend_targets = vec![vec![to_extend_target]; diff as usize];
    targets.extend(to_extend_targets);
    targets
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::tests::extend_to_power_of_two;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::merkle_tree::MerkleTree,
        plonk::config::Hasher,
    };

    use plonky2::{
        field::extension::Extendable,
        hash::{
            hash_types::{HashOut, RichField},
            poseidon::PoseidonHash,
        },
    };

    type F = GoldilocksField;
    const D: usize = 2;

    fn merkle_root<F: RichField + Extendable<D>, const D: usize>(
        leaves: Vec<Vec<F>>,
    ) -> Vec<HashOut<F>> {
        // extend `targets` to a length of power of two vector
        let leaves = extend_to_power_of_two::<F, D>(leaves, F::ZERO);
        // build the merkle tree root target
        let merkle_tree_height = leaves.len().ilog2();
        let mut tree_hash_leaves = vec![];
        for i in 0..leaves.len() {
            let hash = PoseidonHash::hash_or_noop(&leaves[i]);
            tree_hash_leaves.push(hash);
        }
        let mut current_tree_height_index = 0;
        let mut i = 0;
        for height in 0..merkle_tree_height {
            // TODO: do we want to loop over all the height, or until cap(1) ?
            while i < current_tree_height_index + (1 << (merkle_tree_height - height)) {
                let hash = PoseidonHash::hash_no_pad(
                    &[
                        tree_hash_leaves[i as usize].elements.clone(),
                        tree_hash_leaves[i as usize + 1].elements.clone(),
                    ]
                    .concat(),
                );
                tree_hash_leaves.push(hash);
                i += 2;
            }
            current_tree_height_index += 1 << (merkle_tree_height - height);
        }
        tree_hash_leaves
    }

    #[test]
    fn test_merkle_root() {
        let leaves = vec![
            vec![F::ZERO],
            vec![F::ONE],
            vec![F::from_canonical_u64(2)],
            vec![F::from_canonical_u64(3)],
        ];

        let digests = merkle_root::<F, D>(leaves.clone());
        let tree = MerkleTree::<F, PoseidonHash>::new(leaves, 0);

        assert_eq!(*digests.last().unwrap(), tree.cap.0[0]);
    }

    #[test]
    fn test_merkle_root_2() {
        let leaves = vec![
            vec![F::ZERO],
            vec![F::ONE],
            vec![F::from_canonical_u64(2)],
            vec![F::from_canonical_u64(3)],
            vec![F::from_canonical_u64(4)],
        ];

        let digests = merkle_root::<F, D>(leaves.clone());
        let leaves = extend_to_power_of_two::<F, D>(leaves, F::ZERO);
        let tree = MerkleTree::<F, PoseidonHash>::new(leaves, 0);

        assert_eq!(*digests.last().unwrap(), tree.cap.0[0]);
    }
}
