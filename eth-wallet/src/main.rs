use eth_wallet::wallet::{generate_random_message, verify_signature, ETHWallet, Wallet};
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};
use solina::{circuit::ECDSAIntentCircuit, witness::ECDSAIntentWitness, D, F};

fn main() {
    let wallet = Wallet::initialize_new_wallet();
    let public_key = wallet.get_public_key();
    let message = generate_random_message();
    let signature = wallet.sign_message(&message);
    verify_signature(&message, &signature, &public_key);

    let config = CircuitConfig::standard_ecc_config();
    let mut circuit_builder = CircuitBuilder::<F, D>::new(config);
    let ecdsa_signature_targets = circuit_builder.verify_intent_signature();

    let mut partial_witness = PartialWitness::<F>::new();

    let plonky2_public_key = public_key.into_plonky2_public_key();
    let plonky2_message = message.into_plonky2_message();
    let plonky2_signature = signature.into_plonky2_signature();
    partial_witness.verify_signed_intent(
        &mut circuit_builder,
        plonky2_message,
        plonky2_public_key,
        plonky2_signature,
        ecdsa_signature_targets,
    );

    let circuit_data = circuit_builder.build::<PoseidonGoldilocksConfig>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to generate proof for ecdsa signature circuit");

    circuit_data
        .verify(proof_with_pis)
        .expect("Failed to verify proof for ecdsa signature circuit");
}
