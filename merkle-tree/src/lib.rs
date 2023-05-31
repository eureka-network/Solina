use anyhow::anyhow;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    hash::{hash_types::HashOutTarget, merkle_tree::MerkleTree},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use tree_circuit_generation::MerkleRootGenerationBuilder;

mod tests;
mod tree_circuit_generation;
mod utils;

pub trait Provable<F: RichField + Extendable<D>, const D: usize> {
    type Value;
    type Targets;
    type OutTargets;

    fn evaluate(&self) -> Self::Value;
    fn compile(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets);
    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error>;
    fn compile_and_fill(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        self.compile(circuit_builder);
        self.fill(partial_witness, targets, out_targets)
    }
}

impl<const D: usize, F, H> Provable<F, D> for MerkleTree<F, H>
where
    F: RichField + Extendable<D>,
    H: AlgebraicHasher<F>,
{
    type Value = H::Hash;
    type Targets = Vec<Vec<Target>>;
    type OutTargets = HashOutTarget;

    fn evaluate(&self) -> Self::Value {
        // for now, we only allow cap == 0
        if self.cap.len() != 1 {
            panic!("Invalid cap, for now cap == 0")
        }
        self.cap.0[0]
    }

    fn compile(
        &self,
        circuit_builder: &mut CircuitBuilder<F, D>,
    ) -> (Self::Targets, Self::OutTargets) {
        let targets = self
            .leaves
            .iter()
            .map(|l| circuit_builder.add_virtual_targets(l.len()))
            .collect::<Vec<_>>();
        let to_extend_target = circuit_builder.zero();
        let out_target =
            <CircuitBuilder<F, D> as MerkleRootGenerationBuilder<D, F, H>>::add_merkle_root_target(
                circuit_builder,
                targets.clone(),
                to_extend_target,
            );
        (targets, out_target)
    }

    fn fill(
        &self,
        partial_witness: &mut PartialWitness<F>,
        targets: Self::Targets,
        out_targets: Self::OutTargets,
    ) -> Result<(), anyhow::Error> {
        if targets.len() != self.leaves.len() {
            return Err(anyhow!("Invalid target lenghts"));
        }
        targets
            .iter()
            .zip(&self.leaves)
            .map(|(vec_target, leaf)| {
                if vec_target.len() != leaf.len() {
                    Err(anyhow!("Invalid leaf targets length"))
                } else {
                    vec_target
                        .iter()
                        .zip(leaf)
                        .for_each(|(t, l)| partial_witness.set_target(*t, *l));
                    Ok(())
                }
            })
            .collect::<Result<(), _>>()?;
        if self.cap.len() != 1 {
            return Err(anyhow!("Invalid cap, for now cap == 0"));
        }
        partial_witness.set_hash_target(out_targets, self.cap.0[0]);
        Ok(())
