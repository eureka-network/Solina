pub mod encode_values;
pub mod types;

use hex::encode;
use keccak_hash::keccak;
use rand::{rngs::OsRng, RngCore};
use types::{Salt, StructuredHash};

use crate::types::{Address, EncodedValue};

pub trait StructuredHashIntentInterface {
    fn name() -> &'static str;
    fn input_names() -> Vec<&'static str>;
    fn input_types() -> Vec<&'static str>;
    fn constraint_names() -> Vec<&'static str>;
    fn constraint_inputs() -> Vec<&'static str>;
    // TODO: for now we leave recursion out of the picture
    fn encoding(&self) -> String {
        let input_names = Self::input_names();
        let input_types = Self::input_types();
        if input_names.len() != input_types.len() {
            panic!("Input names and input types have distinct lengths");
        }
        let parsed_input = input_names
            .into_iter()
            .zip(input_types)
            .map(|(n, t)| format!("{} {}", t, n))
            .collect::<Vec<String>>()
            .join(",");
        format!("{}({})", Self::name(), parsed_input)
    }
    fn structured_hash(&self, domain_separator: Option<String>) -> StructuredHash;
}

pub enum EncodedValues {
    Bool(bool),
    Integer,
    Address,
    Bytes,
    String,
    Array,
}

#[derive(Debug)]
pub struct EIP712Domain {
    name: String,
    version: u32,
    chain_id: u16,
    verifying_contract: Address,
    salt: Salt,
}

impl EIP712Domain {
    fn new(
        name: String,
        version: u32,
        chain_id: u16,
        verifying_contract: Address,
        salt: Option<Salt>,
    ) -> Self {
        let salt = salt.unwrap_or_else(|| {
            let mut salt = [0u8; 32];
            OsRng.fill_bytes(&mut salt);
            salt
        });
        Self {
            name,
            version,
            chain_id,
            verifying_contract,
            salt,
        }
    }

    fn to_domain_separator_string(&self) -> String {
        format!(
            "<EIP712DOMAIN><name:{}><version:{}><chain_id:{}><verifying_contract:{}><salt:{}>",
            self.name,
            self.version,
            self.chain_id,
            encode(self.verifying_contract),
            encode(self.salt)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStruct {
        name: String,
        address: Address,
        version: u32,
    }

    impl StructuredHashIntentInterface for TestStruct {
        fn name() -> &'static str {
            "TestStruct"
        }

        fn input_names() -> Vec<&'static str> {
            vec!["name", "address", "version"]
        }

        fn input_types() -> Vec<&'static str> {
            vec!["String", "Address", "u32"]
        }

        fn constraint_inputs() -> Vec<&'static str> {
            vec![]
        }

        fn constraint_names() -> Vec<&'static str> {
            vec![]
        }

        fn structured_hash(&self, domain_separator: Option<String>) -> StructuredHash {
            todo!()
        }
    }
}
