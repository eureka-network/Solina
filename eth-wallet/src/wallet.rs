use conversions::types::{Message, PrivateKey, PublicKey, Signature};
use libsecp256k1::{sign, verify};
use rand::Rng;

pub trait ETHWallet {
    fn initialize_new_wallet() -> Self;
    fn initialize_from_private_key(private_key: PrivateKey) -> Self;
    fn sign_message(self, message: &Message) -> Signature;
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
        self.public_key.clone()
    }

    fn sign_message(self, message: &Message) -> Signature {
        let (signature, _) = sign(
            message.as_libsecp256k1_message(),
            &self.private_key.into_secret_key(),
        );
        Signature::new(signature)
    }
}

pub fn verify_signature(message: &Message, signature: &Signature, public_key: &PublicKey) -> bool {
    verify(
        message.as_libsecp256k1_message(),
        signature.as_libsecp256k1_signature(),
        public_key.as_libsecp256k1_public_key(),
    )
}

pub fn generate_random_message() -> Message {
    let data = rand::thread_rng().gen::<[u8; 32]>();
    println!("data = {:?}", data);
    let message = Message::new_message(data);
    message
}

#[cfg(test)]
mod tests {
    use plonky2_ecdsa::curve::ecdsa::verify_message;

    use super::*;

    #[test]
    fn it_works_signature_scheme_libsecp256k1_plonky2_conversion() {
        let wallet = Wallet::initialize_new_wallet();
        let message = generate_random_message();
        let public_key = wallet.get_public_key();

        let signature = wallet.sign_message(&message);

        let plonky2_message = message.into_plonky2_message();
        let plonky2_public_key = public_key.into_plonky2_public_key();
        let plonky2_signature = signature.clone().into_plonky2_signature();

        assert!(verify_message(
            plonky2_message,
            plonky2_signature,
            plonky2_public_key
        ));
    }

    #[test]
    fn it_works_signature_scheme_libsecp256k1_plonky2_wallet() {
        let wallet = Wallet::initialize_new_wallet();
        let message = generate_random_message();
        let public_key = wallet.get_public_key();

        let signature = wallet.sign_message(&message);

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
