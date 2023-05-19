use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

#[allow(dead_code)]
pub struct SwapIntent {
    from: BigUintTarget,
    quote_tokens: BigUintTarget,
    base_tokens: BigUintTarget,
    // send
}
