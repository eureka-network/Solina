use crate::types::EncodedValue;

fn encode_bool_value(value: bool) -> EncodedValue {
    let mut data = [0u8; 32];
    if value {
        data[0] = 1;
    }
    data
}
