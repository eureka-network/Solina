use plonky2::field::goldilocks_field::GoldilocksField;

pub mod crypto;
pub mod error;
pub mod proof;

pub type F = GoldilocksField;
pub const D: usize = 2;
