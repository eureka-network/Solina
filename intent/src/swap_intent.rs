use plonky2_ecdsa::gadgets::biguint::BigUintTarget;

pub struct SwapIntent {
    from: BigUintTarget,
    quote_tokens: BigUintTarget,
    base_tokens: BigUintTarget,
    // send
}
