use keccak_hash::keccak;

#[allow(dead_code)]
pub(crate) type StructuredHash = [u8; 32];

pub trait StructuredHashInterface {
    fn type_encode() -> String;
    fn data_encode(&self) -> Vec<u8>;
    fn structured_hash(&self) -> StructuredHash {
        let type_encoding = keccak(&Self::type_encode()).to_fixed_bytes();
        let data_encoding = keccak(&self.data_encode()).to_fixed_bytes();
        let output = keccak(&[type_encoding, data_encoding].concat());
        output.to_fixed_bytes()
    }
}
