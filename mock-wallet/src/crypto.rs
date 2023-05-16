use num_bigint::BigUint;
use plonky2::field::types::Field;
use plonky2_ecdsa::curve::ecdsa::{ECDSAPublicKey, ECDSASecretKey};
use secp256k1::ecdsa::Signature;
use secp256k1::hashes::sha256;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{KeyPair, Message, PublicKey, Secp256k1, SecretKey};

pub trait MockWallet {
    fn initialize_wallet() -> Self;
    fn get_public_key(&self) -> PublicKey;
    fn get_public_key_plonky2_format(&self) -> ECDSAPublicKey<C>;
    fn sign_message(&self, message: &Message) -> Signature;
    fn verify_message(&self, message: &Message, signature: &Signature) -> bool;
}

pub type C = plonky2_ecdsa::curve::secp256k1::Secp256K1;

pub struct Wallet {
    private_key: SecretKey,
}

impl MockWallet for Wallet {
    fn initialize_wallet() -> Self {
        let secp = Secp256k1::new();
        let (private_key, _public_key) = secp.generate_keypair(&mut OsRng);
        panic!(
            "FLAG: public key length = {}",
            _public_key.x_only_public_key().0
        );
        Self { private_key }
    }

    fn get_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.private_key)
    }

    fn get_public_key_plonky2_format(&self) -> ECDSAPublicKey<C> {
        let secret_key_slice = &self.private_key.secret_bytes()[..];
        let secret_key_biguint = BigUint::from_bytes_le(secret_key_slice);
        let secp256k1_scalar_noncanonical_sk =
            plonky2::field::secp256k1_scalar::Secp256K1Scalar::from_noncanonical_biguint(
                secret_key_biguint,
            );
        let secret_key: ECDSASecretKey<C> = ECDSASecretKey(secp256k1_scalar_noncanonical_sk);
        let public_key = secret_key.to_public();
        public_key
    }

    fn sign_message(&self, message: &Message) -> Signature {
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(message, &self.private_key);
        signature
    }

    fn verify_message(&self, message: &Message, signature: &Signature) -> bool {
        let secp = Secp256k1::new();
        let public_key = self.get_public_key();
        secp.verify_ecdsa(message, signature, &public_key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hex_literal::hex;
    use num_bigint::BigUint;
    use plonky2::field::{
        packed::PackedField,
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field, PrimeField, Sample},
    };
    use plonky2_ecdsa::curve::ecdsa::{sign_message, verify_message, ECDSASecretKey};
    use secp256k1::{ecdh::shared_secret_point, rand::RngCore};

    use super::*;

    #[test]
    fn it_works_signature() {
        let secp = Secp256k1::new();
        let wallet = Wallet::initialize_wallet();
        let public_key = wallet.get_public_key();

        let mut data = [0u8; 32];
        OsRng.fill_bytes(&mut data);

        let message = Message::from_hashed_data::<sha256::Hash>(&data);

        dbg!(message);

        let signature = wallet.sign_message(&message);
        assert!(secp.verify_ecdsa(&message, &signature, &public_key).is_ok());
    }

    #[test]
    fn aux_test() {
        type C = plonky2_ecdsa::curve::secp256k1::Secp256K1;

        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<C>(Secp256K1Scalar::rand());
        let pk = sk.to_public();
        let sig = sign_message(msg, sk);

        assert!(verify_message(msg, sig, pk));

        let secp = Secp256k1::new();
        let msg = Message::from_slice(
            &msg.0
                .iter()
                .flat_map(|a| a.to_le_bytes())
                .collect::<Vec<u8>>(),
        )
        .unwrap();
        let private_key = sk.0.to_canonical_biguint().to_bytes_le();
        let secret_key = SecretKey::from_slice(&private_key).unwrap();
        let public_key = secret_key.public_key(&secp);
        let should_be_public_key = PublicKey::from_slice(
            &[
                pk.0.x
                    .0
                    .iter()
                    .flat_map(|a| a.to_le_bytes())
                    .collect::<Vec<_>>(),
                pk.0.y
                    .0
                    .iter()
                    .flat_map(|a| a.to_le_bytes())
                    .collect::<Vec<_>>(),
            ]
            .concat(),
        )
        .unwrap();

        assert_eq!(public_key, should_be_public_key);

        // let message = msg
        //     .0
        //     .iter()
        //     .flat_map(|a| a.to_le_bytes())
        //     .collect::<Vec<u8>>();
        // let private_key = sk.0.to_canonical_biguint().to_bytes_le();
        // let signature = [
        //     sig.r.to_canonical_biguint().to_bytes_le(),
        //     sig.s.to_canonical_biguint().to_bytes_le(),
        // ]
        // .concat();

        // let secp = Secp256k1::new();
        // let secret_key = SecretKey::from_slice(&private_key).unwrap();
        // let public_key = secret_key.public_key(&secp);
        // let signature = Signature::from_compact(&signature).unwrap();
        // let message = Message::from_slice(&message);

        // verify_message(msg, sig, pk);
    }

    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    #[test]
    fn aux_test1() {
        type C = plonky2_ecdsa::curve::secp256k1::Secp256K1;

        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<C>(Secp256K1Scalar::rand());
        let pk = sk.to_public();
        let sig = sign_message(msg, sk);

        let secp = Secp256k1::new();
        let data =
            sk.0 .0
                .iter()
                .flat_map(|u| u.to_be_bytes())
                .collect::<Vec<u8>>();
        let aux_sk = SecretKey::from_slice(&data).unwrap();

        assert_eq!(aux_sk.as_ref(), data.as_slice());
        let aux_pk = aux_sk.public_key(&secp);
        println!(
            "FLAG: PUBLIC KEY = {:?}",
            BigUint::from_bytes_be(&aux_pk.x_only_public_key().0.serialize()[1..])
        );
        let public_key_x = pk.0.x.to_canonical_biguint();
        let public_key_y = pk.0.y.to_canonical_biguint();
        println!("FLAG: public key = {:?}", public_key_x);
    }

    #[test]
    fn test_curve_generators() {
        let gen_x_u64: [u64; 4] = [
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        ];
        let gen_x_u8 = gen_x_u64
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>();
        let other_gen_x_u8: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];

        let gen_y_u64: [u64; 4] = [
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ];
        let gen_y_u8 = gen_y_u64
            .iter()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<u8>>();
        let other_gen_y_u8: [u8; 32] = [
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
            0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
            0xfb, 0x10, 0xd4, 0xb8,
        ];

        assert_eq!(
            BigUint::from_bytes_le(&gen_x_u8),
            BigUint::from_bytes_be(&other_gen_x_u8)
        );
        assert_eq!(
            BigUint::from_bytes_le(&gen_y_u8),
            BigUint::from_bytes_be(&other_gen_y_u8)
        )
    }
}
