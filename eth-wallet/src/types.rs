use libsecp256k1::{
    curve::{Affine, Scalar},
    Message, PublicKeyFormat, SecretKey,
};
use num_bigint::BigUint;
use plonky2::{
    field::{secp256k1_scalar::Secp256K1Scalar, types::Field},
    iop::witness::PartialWitness,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::{
    curve::{ecdsa::ECDSASecretKey, secp256k1::Secp256K1},
    gadgets::biguint::{BigUintTarget, WitnessBigUint},
};

use crate::{
    crypto::{ETHWallet, Wallet},
    error::TypeConversionError,
    D, F,
};

pub struct PrivateKey(SecretKey);

impl PrivateKey {
    /// Initializes a [`PrivateKey`] from a libsecp256k1 [`SecretKey`] instance.
    fn from_secret_key(sk: SecretKey) -> Self {
        PrivateKey(sk)
    }

    /// Returns a libsecp256k1's [`SecretKey`] instance from a [`PrivateKey`] instance.
    fn into_secret_key(self) -> SecretKey {
        self.0
    }

    /// Initializes a [`PrivateKey`] from a plonky2_ecdsa [`ECDSASecretKey`] instance.
    /// We have to convert data representation from little endian byte (plonky2_ecdsa) to
    /// big endian byte representation (libsecp256k1).
    fn from_plonky2_secret_key(
        plonky2_secret_key: ECDSASecretKey<Secp256K1>,
    ) -> Result<Self, TypeConversionError> {
        let mut u64_plonky2_secret_key: [u64; 4] = plonky2_secret_key.0 .0;
        // we can first reverse the order of the elements of the array
        u64_plonky2_secret_key.reverse();
        // and then reverse the byte ordering of each element, to do a full byte reordering
        let big_end_bytes_secret_key = u64_plonky2_secret_key
            .iter()
            .flat_map(|u| u.to_be_bytes())
            .collect::<Vec<u8>>();
        // specify an array of 32-bytes from `u8_big_end_bytes_secret_key`
        let mut secret_key_big_end_byte_array = [0u8; 32];
        secret_key_big_end_byte_array.copy_from_slice(&big_end_bytes_secret_key);
        let libsecp256k1_sk = SecretKey::parse(&secret_key_big_end_byte_array)
            .map_err(|e| TypeConversionError::InvalidLibSecp256K1TypeConversion(e))?;
        Ok(Self(libsecp256k1_sk))
    }
}

pub struct PublicKey(libsecp256k1::PublicKey);

impl PublicKey {
    fn from_private_key(private_key: &PrivateKey) -> Self {
        PublicKey(libsecp256k1::PublicKey::from_secret_key(&private_key.0))
    }

    fn from_plonky2_secret_key(
        plonky2_secret_key: &ECDSASecretKey<Secp256K1>,
    ) -> Result<Self, TypeConversionError> {
        let plonky2_public_key = plonky2_secret_key.to_public();
        let plonky2_public_key_x = plonky2_public_key.0.x;
        let plonky2_public_key_y = plonky2_public_key.0.y;
        let plonky2_public_key_x_be_bytes = plonky2_public_key_x
            .0
            .iter()
            .rev()
            .flat_map(|u| u.to_be_bytes())
            .collect::<Vec<_>>();
        let plonky2_public_key_y_be_bytes = plonky2_public_key_y
            .0
            .iter()
            .rev()
            .flat_map(|u| u.to_be_bytes())
            .collect::<Vec<_>>();
        let public_key = libsecp256k1::PublicKey::parse_slice(
            &[plonky2_public_key_x_be_bytes, plonky2_public_key_y_be_bytes].concat(),
            Some(PublicKeyFormat::Full),
        )?;
        // we assert infinity == false, as plonky2 affine points
        Ok(Self(public_key))
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::{
        secp256k1_scalar::Secp256K1Scalar,
        types::{PrimeField, Sample},
    };

    use super::*;

    #[test]
    fn it_works_private_key_from_plonky2_sk() {
        let plonky2_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let private_key = PrivateKey::from_plonky2_secret_key(plonky2_sk).unwrap();
        // assert that the [`BigUint`] representations match
        assert_eq!(
            BigUint::from_bytes_le(
                &plonky2_sk
                    .0
                     .0
                    .iter()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<_>>()
            ),
            BigUint::from_bytes_be(&private_key.0.serialize())
        );
    }

    #[test]
    fn it_works_plonky2_libsecp256k1_public_key_coordinates() {
        let plonky2_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let private_key = PrivateKey::from_plonky2_secret_key(plonky2_sk).unwrap();
        let plonky2_public_key = plonky2_sk.to_public();
        let public_key = libsecp256k1::PublicKey::from_secret_key(&private_key.0);

        // assert that both x coordinates of public key match
        assert_eq!(
            BigUint::from_bytes_be(&public_key.serialize()[1..33]),
            plonky2_public_key.0.x.to_canonical_biguint()
        );
        // assert that both y coordinates of public key match
        assert_eq!(
            BigUint::from_bytes_be(&public_key.serialize()[33..65]),
            plonky2_public_key.0.y.to_canonical_biguint()
        );
    }
}
