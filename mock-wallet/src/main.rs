use hex_literal::{decode, hex};
use intent::{circuit::ECDSAIntentCircuit, witness::ECDSAIntentWitness, D, F, FF};
use mock_wallet::crypto::{MockWallet, Wallet};
use num_bigint::BigUint;
use plonky2::{
    field::{secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar, types::Field},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
        config::PoseidonGoldilocksConfig,
    },
};
use plonky2_ecdsa::curve::{
    curve_types::AffinePoint,
    ecdsa::{ECDSAPublicKey, ECDSASignature},
};
use secp256k1::{
    ecdsa::Signature,
    hashes::sha256,
    rand::{rngs::OsRng, RngCore},
    Message, Secp256k1,
};

fn main() {
    //     let secp = Secp256k1::new();
    //     let wallet = Wallet::initialize_wallet();
    //     let public_key = wallet.get_public_key();

    //     let mut data = [0u8; 32];
    //     OsRng.fill_bytes(&mut data);

    //     let message = Message::from_hashed_data::<sha256::Hash>(&data);
    //     let signature = wallet.sign_message(&message);
    //     if let Err(e) = secp.verify_ecdsa(&message, &signature, &public_key) {
    //         panic!(
    //             "Failed to verify ecdsa signature for message: {} and public key: {} with error: {}",
    //             message, public_key, e
    //         );
    //     }

    //     let config = CircuitConfig::standard_ecc_config();
    //     let mut circuit_builder = CircuitBuilder::<F, D>::new(config);

    //     let targets = circuit_builder.verify_intent_signature();

    //     let mut partial_witness = PartialWitness::<F>::new();

    //     let message = FF::from_noncanonical_biguint(BigUint::from_bytes_le(message.as_ref()));
    //     let public_key = wallet.get_public_key_plonky2_format();

    //     let signature = signature.serialize_compact();
    //     let r = &signature[..32];
    //     let s = &signature[32..];
    //     let r_biguint = BigUint::from_bytes_le(r);
    //     let s_biguint = BigUint::from_bytes_le(s);
    //     let r_secp = Secp256K1Scalar::from_noncanonical_biguint(r_biguint);
    //     let s_secp = Secp256K1Scalar::from_noncanonical_biguint(s_biguint);
    //     let signature = ECDSASignature {
    //         r: r_secp,
    //         s: s_secp,
    //     };

    //     partial_witness.verify_signed_intent(
    //         &mut circuit_builder,
    //         message,
    //         public_key,
    //         signature,
    //         targets,
    //     );

    //     let circuit_data = circuit_builder.build::<PoseidonGoldilocksConfig>();
    //     let proof = circuit_data
    //         .prove(partial_witness)
    //         .expect("Faild to prove circuit");
}
