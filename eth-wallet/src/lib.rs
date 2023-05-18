use plonky2::field::goldilocks_field::GoldilocksField;

pub mod error;
pub mod proof;
pub mod wallet;

pub type F = GoldilocksField;
pub const D: usize = 2;
