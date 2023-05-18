use crate::error::TypeConversionError;

/// Converts a slice of u64 digits, supposed to be represented in little endian form,
///  into a byte array in big endian form. The generic constant `N` corresponds to the
/// byte size of the outputed array, thus `N = 8 * slice.len()`.
pub fn convert_u64_le_to_u8_be<const N: usize>(
    slice: &[u64],
) -> Result<[u8; N], TypeConversionError> {
    if 8 * slice.len() != N {
        return Err(TypeConversionError::InvalidSliceLength(slice.len(), N));
    }

    let mut data = [0u8; N];
    let be_bytes_slice = slice
        .iter()
        .rev()
        .flat_map(|u| u.to_be_bytes())
        .collect::<Vec<_>>();
    data.copy_from_slice(&be_bytes_slice);

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works_convert_u64_le_to_u8_be() {
        let slice = [0u64, 1, 2, 3];
        let mut u8_be_slice = convert_u64_le_to_u8_be::<32>(&slice).unwrap();
        u8_be_slice.reverse();
        let mut u64_le_slice = [0u64; 4];
        (0..4).rev().for_each(|i| {
            println!("{}", i);
            let mut data = [0u8; 8];
            data.copy_from_slice(&u8_be_slice[4 * i..(4 * i + 8)]);
            let u64_val = u64::from_be_bytes(data);
            u64_le_slice[i] = u64_val;
        });
        assert_eq!(slice, u64_le_slice);
    }
}
