use libsecp256k1::{sign, verify, Message, PublicKey, SecretKey, Signature};
use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
use rand::rngs::OsRng;

pub trait ETHWallet {
    fn initialize_new_wallet() -> Self;
    fn initialize_from_private_key(private_key: SecretKey) -> Self;
    fn sign_message(&self, message: &Message) -> Signature;
    fn get_public_key(&self) -> PublicKey;
}

pub type C = plonky2_ecdsa::curve::secp256k1::Secp256K1;

pub struct Wallet {
    private_key: SecretKey,
    public_key: PublicKey,
}

impl ETHWallet for Wallet {
    fn initialize_new_wallet() -> Self {
        let mut rng = OsRng;
        let private_key = SecretKey::random(&mut rng);
        let public_key = PublicKey::from_secret_key(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    fn initialize_from_private_key(private_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    fn get_public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign_message(&self, message: &Message) -> Signature {
        let (signature, _) = sign(&message, &self.private_key);
        signature
    }
}

pub fn verify_signature(message: &Message, signature: &Signature, public_key: &PublicKey) -> bool {
    verify(message, signature, public_key)
}

#[cfg(test)]
mod tests {
    use libsecp256k1::curve::Scalar;
    use rand::RngCore;

    use super::*;

    #[test]
    fn it_works_verify_signature() {
        let wallet = Wallet::initialize_new_wallet();
        let mut data = [0u32; 8];
        (0..8).for_each(|i| data[i] = OsRng.next_u32());
        println!("data = {:?}", data);
        let message = Message(Scalar(data));
        let signature = wallet.sign_message(&message);
        let public_key = wallet.get_public_key();
        assert!(verify_signature(&message, &signature, &public_key));
    }
}
