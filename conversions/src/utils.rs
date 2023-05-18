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
    use num_bigint::BigUint;

    #[test]
    fn it_works_convert_u64_le_to_u8_be() {
        let slice = [0u64, 1, 2, 3];
        let u8_be_slice = convert_u64_le_to_u8_be::<32>(&slice).unwrap();
        assert_eq!(
            BigUint::from_bytes_be(&u8_be_slice),
            BigUint::from_bytes_le(
                &slice
                    .iter()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<_>>()
            )
        );
    }
}
