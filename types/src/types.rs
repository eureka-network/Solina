use libsecp256k1::{PublicKeyFormat, SecretKey};
use num_bigint::BigUint;
use plonky2::field::{
    secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar, types::Field,
};
use plonky2_ecdsa::curve::{
    curve_types::AffinePoint,
    ecdsa::{ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};
use rand::rngs::OsRng;

use crate::{error::TypeConversionError, utils::convert_u64_le_to_u8_be};

pub struct PrivateKey(pub(crate) SecretKey);

impl PrivateKey {
    /// Initializes a [`PrivateKey`] randomly
    pub fn new() -> Self {
        let mut rng = OsRng;
        let secret_key = SecretKey::random(&mut rng);
        Self(secret_key)
    }

    /// Initializes a [`PrivateKey`] from a libsecp256k1 [`SecretKey`] instance.
    #[allow(dead_code)]
    fn from_secret_key(sk: SecretKey) -> Self {
        PrivateKey(sk)
    }

    /// Returns a libsecp256k1's [`SecretKey`] instance from a [`PrivateKey`] instance.
    pub fn into_secret_key(self) -> SecretKey {
        self.0
    }

    /// Initializes a [`PrivateKey`] from a plonky2_ecdsa [`ECDSASecretKey`] instance.
    /// We have to convert data representation from little endian byte (plonky2_ecdsa) to
    /// big endian byte representation (libsecp256k1).
    fn from_plonky2_secret_key(
        plonky2_secret_key: ECDSASecretKey<Secp256K1>,
    ) -> Result<Self, TypeConversionError> {
        let u64_plonky2_secret_key: [u64; 4] = plonky2_secret_key.0 .0;
        // we can first reverse the order of the elements of the array
        // and then reverse the byte ordering of each element, to do a full byte reordering
        let big_end_bytes_secret_key = convert_u64_le_to_u8_be::<32>(&u64_plonky2_secret_key)
            .expect("Failed to convert u64 slice to le bytes");
        // specify an array of 32-bytes from `u8_big_end_bytes_secret_key`
        let mut secret_key_big_end_byte_array = [0u8; 32];
        secret_key_big_end_byte_array.copy_from_slice(&big_end_bytes_secret_key);
        let libsecp256k1_sk = SecretKey::parse(&secret_key_big_end_byte_array)
            .map_err(|e| TypeConversionError::InvalidLibSecp256K1TypeConversion(e))?;
        Ok(Self(libsecp256k1_sk))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey(pub(crate) libsecp256k1::PublicKey);

impl PublicKey {
    pub fn new(public_key: libsecp256k1::PublicKey) -> Self {
        Self(public_key)
    }

    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        PublicKey(libsecp256k1::PublicKey::from_secret_key(&private_key.0))
    }

    pub fn from_plonky2_secret_key(
        plonky2_secret_key: &ECDSASecretKey<Secp256K1>,
    ) -> Result<Self, TypeConversionError> {
        let private_key = PrivateKey::from_plonky2_secret_key(*plonky2_secret_key)?;
        Ok(Self::from_private_key(&private_key))
    }

    pub fn as_libsecp256k1_public_key<'a>(&'a self) -> &'a libsecp256k1::PublicKey {
        &self.0
    }

    pub fn from_plonky2_public_key(
        plonky2_public_key: ECDSAPublicKey<Secp256K1>,
    ) -> Result<Self, TypeConversionError> {
        let plonky2_public_key_x = plonky2_public_key.0.x;
        let plonky2_public_key_y = plonky2_public_key.0.y;
        let plonky2_public_key_x_be_bytes = convert_u64_le_to_u8_be::<32>(&plonky2_public_key_x.0)
            .expect("Failed to convert u64 slice to be bytes");
        let plonky2_public_key_y_be_bytes = convert_u64_le_to_u8_be::<32>(&plonky2_public_key_y.0)
            .expect("Failed to convert u64 slice to le bytes");
        let public_key = libsecp256k1::PublicKey::parse_slice(
            &[plonky2_public_key_x_be_bytes, plonky2_public_key_y_be_bytes].concat(),
            Some(PublicKeyFormat::Raw),
        )?;
        Ok(Self(public_key))
    }

    pub fn into_plonky2_public_key(self) -> ECDSAPublicKey<Secp256K1> {
        let serialized_public_key_be_bytes = self.0.serialize();
        let public_key_be_bytes_x = &serialized_public_key_be_bytes[1..33];
        let public_key_be_bytes_y = &serialized_public_key_be_bytes[33..65];
        let plonky2_public_key = ECDSAPublicKey(AffinePoint::nonzero(
            Secp256K1Base::from_noncanonical_biguint(BigUint::from_bytes_be(
                &public_key_be_bytes_x,
            )),
            Secp256K1Base::from_noncanonical_biguint(BigUint::from_bytes_be(
                &public_key_be_bytes_y,
            )),
        ));
        plonky2_public_key
    }
}

pub struct Message(pub(crate) libsecp256k1::Message);

impl Message {
    pub fn new_message(data: [u8; 32]) -> Self {
        Self(libsecp256k1::Message::parse(&data))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, TypeConversionError> {
        Ok(Self(libsecp256k1::Message::parse_slice(slice).map_err(
            |e| TypeConversionError::InvalidLibSecp256K1TypeConversion(e),
        )?))
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0.serialize()
    }

    pub fn as_libsecp256k1_message<'a>(&'a self) -> &'a libsecp256k1::Message {
        &self.0
    }

    pub fn into_plonky2_message(self) -> Secp256K1Scalar {
        let message_bytes = self.into_bytes();
        // The probability that a message of 32-bytes doesn't fit
        // into the Secp256k1 scalar field order is around 10 ** (-39).
        // This is roughly a probability of (2 ** 128)^{-1}, therefore
        // we can safely assume that such `BigUint` message instance, will
        // fit in [`Secp256K1Scalar`]
        Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&message_bytes))
    }
}

#[derive(Clone)]
pub struct Signature(pub(crate) libsecp256k1::Signature);

impl Signature {
    pub fn new(signature: libsecp256k1::Signature) -> Self {
        Self(signature)
    }

    pub fn as_libsecp256k1_signature<'a>(&'a self) -> &'a libsecp256k1::Signature {
        &self.0
    }

    pub fn into_plonky2_signature(self) -> ECDSASignature<Secp256K1> {
        let signature = self.0;
        // as be bytes
        let r = signature.r.b32();
        let s = signature.s.b32();
        // both r and s are values in the Secpk1 scalar field, as the signature
        // is generated with libsecp256k1, this means we can use
        // `from_noncanonical_biguint` to get well defined values in [`Secp256K1Scalar`]
        ECDSASignature {
            r: Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&r)),
            s: Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&s)),
        }
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

        // assert that both x coordinates of public keys match
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

    #[test]
    fn it_works_pubkey_from_plonky2_sk() {
        let plonky2_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let public_key = PublicKey::from_plonky2_secret_key(&plonky2_sk).unwrap();
        let should_be_public_key =
            PublicKey::from_private_key(&PrivateKey::from_plonky2_secret_key(plonky2_sk).unwrap());
        assert_eq!(public_key, should_be_public_key);
    }

    #[test]
    fn it_works_plonky2_libsecp256k1_public_key_conversion() {
        let plonky2_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let private_key = PrivateKey::from_plonky2_secret_key(plonky2_sk).unwrap();
        let plonky2_public_key = plonky2_sk.to_public();
        let public_key = PublicKey::from_plonky2_public_key(plonky2_public_key).unwrap();
        let should_be_public_key = PublicKey::from_private_key(&private_key);
        // assert that both x coordinates of public keys match
        assert_eq!(public_key, should_be_public_key);
    }

    #[test]
    fn it_works_libsecp256k1_plonky2_public_key_conversion() {
        let plonky2_sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
        let private_key = PrivateKey::from_plonky2_secret_key(plonky2_sk).unwrap();
        let should_be_plonky2_public_key = plonky2_sk.to_public();
        let public_key = PublicKey::from_private_key(&private_key);
        let plonky2_public_key = public_key.into_plonky2_public_key();
        assert_eq!(plonky2_public_key, should_be_plonky2_public_key);
    }
}
