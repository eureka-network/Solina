use libsecp256k1::Message;
use num_bigint::BigUint;
use plonky2::{iop::witness::PartialWitness, plonk::circuit_builder::CircuitBuilder};
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, WitnessBigUint};

use crate::{
    crypto::{ETHWallet, Wallet},
    D, F,
};

// pub trait WitnessVerifySecp256k1 {
//     fn message_witness(&mut self, biguint_target: &BigUintTarget, message: Message) -> BigUint;
// }

// impl WitnessVerifySecp256k1 for PartialWitness<F> {
//     fn message_witness(&mut self, biguint_target: &BigUintTarget, message: Message) -> BigUint {
//         let message_biguint = BigUint::from_bytes_be(&message.0.b32());
//         self.set_biguint_target(&biguint_target, &message_biguint);
//         message_biguint
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works_() {}
}
