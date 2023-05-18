use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use crate::StructuredHash;
/// Intent to swap tokens 
/// todo[ben]: this is incomplete, but let's focus on the pathways first
pub struct SwapIntent {
    /// address
    from: BigUintTarget,
    /// address
    quote_token: BigUintTarget,
    /// address
    base_token: BigUintTarget,
    /// in Wei
    quote_amount: BigUintTarget,
    /// in Wei
    base_amount: BigUintTarget,
}


impl 