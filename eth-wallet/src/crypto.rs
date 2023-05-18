use conversions::{Message, PrivateKey, PublicKey, Signature};
use libsecp256k1::{sign, verify};

pub trait ETHWallet {
    fn initialize_new_wallet() -> Self;
    fn initialize_from_private_key(private_key: PrivateKey) -> Self;
    fn sign_message(&self, message: &Message) -> Signature;
    fn get_public_key(&self) -> PublicKey;
}

pub type C = plonky2_ecdsa::curve::secp256k1::Secp256K1;

pub struct Wallet {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl ETHWallet for Wallet {
    fn initialize_new_wallet() -> Self {
        let private_key = PrivateKey::new();
        let public_key = PublicKey::from_private_key(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    fn initialize_from_private_key(private_key: PrivateKey) -> Self {
        let public_key = PublicKey::from_private_key(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    fn get_public_key(&self) -> PublicKey {
        PublicKey(self.public_key.0.clone())
    }

    fn sign_message(&self, message: &Message) -> Signature {
        let (signature, _) = sign(&message.0, &self.private_key.0);
        Signature(signature)
    }
}

pub fn verify_signature(message: &Message, signature: &Signature, public_key: &PublicKey) -> bool {
    verify(&message.0, &signature.0, &public_key.0)
}

#[cfg(test)]
mod tests {
    use libsecp256k1::curve::Scalar;
    use plonky2_ecdsa::curve::ecdsa::verify_message;
    use rand::{rngs::OsRng, RngCore};

    use super::*;

    #[test]
    fn it_works_verify_signature() {
        let wallet = Wallet::initialize_new_wallet();
        let mut data = [0u32; 8];
        (0..8).for_each(|i| data[i] = OsRng.next_u32());
        println!("data = {:?}", data);
        let message = Message(libsecp256k1::Message(Scalar(data)));
        let signature = wallet.sign_message(&message);
        let public_key = wallet.get_public_key();
        assert!(verify_signature(&message, &signature, &public_key));
    }

    #[test]
    fn it_works_signature_scheme_libsecp256k1_plonky2_conversion() {
        let wallet = Wallet::initialize_new_wallet();
        let mut data = [0u32; 8];
        (0..8).for_each(|i| data[i] = OsRng.next_u32());
        println!("data = {:?}", data);
        let message = Message(libsecp256k1::Message(Scalar(data)));
        let signature = wallet.sign_message(&message);
        let public_key = wallet.get_public_key();

        let plonky2_message = message.into_plonky2_message();
        let plonky2_public_key = public_key.into_plonky2_public_key();
        let plonky2_signature = signature.clone().into_plonky2_signature();

        assert!(verify_message(
            plonky2_message,
            plonky2_signature,
            plonky2_public_key
        ));
    }
}
