use plonky2::{
    field::types::{Field, PrimeField},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use plonky2_ecdsa::{
    curve::ecdsa::{ECDSAPublicKey, ECDSASignature},
    gadgets::{
        biguint::WitnessBigUint, curve::AffinePointTarget, ecdsa::ECDSASignatureTarget,
        nonnative::CircuitBuilderNonNative,
    },
};

use crate::{circuit::ECDSASignatureCircuitTargets, C, D, F, FF};

pub trait ECDSAIntentWitness {
    fn verify_signed_intent(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        message: FF,
        public_key: ECDSAPublicKey<C>,
        signature: ECDSASignature<C>,
        targets: ECDSASignatureCircuitTargets,
    );
}

impl ECDSAIntentWitness for PartialWitness<F> {
    fn verify_signed_intent(
        &mut self,
        circuit_builder: &mut CircuitBuilder<F, D>,
        message: FF,
        public_key: ECDSAPublicKey<C>,
        signature: ECDSASignature<C>,
        targets: ECDSASignatureCircuitTargets,
    ) {
        let ECDSASignatureCircuitTargets {
            message_nonnative_target,
            public_key_ecdsa_target,
            signature_ecdsa_signature_target,
        } = targets;

        let message_biguint_target =
            circuit_builder.nonnative_to_canonical_biguint(&message_nonnative_target);
        self.set_biguint_target(&message_biguint_target, &message.to_canonical_biguint());

        let AffinePointTarget {
            x: x_public_key_target,
            y: y_public_key_target,
        } = public_key_ecdsa_target.0;
        let x_public_key_target =
            circuit_builder.nonnative_to_canonical_biguint(&x_public_key_target);
        let y_public_key_target =
            circuit_builder.nonnative_to_canonical_biguint(&y_public_key_target);
        self.set_biguint_target(&x_public_key_target, &public_key.0.x.to_canonical_biguint());
        self.set_biguint_target(&y_public_key_target, &public_key.0.y.to_canonical_biguint());

        let ECDSASignatureTarget {
            r: r_signature_target,
            s: s_signature_target,
        } = signature_ecdsa_signature_target;
        let r_signature_target =
            circuit_builder.nonnative_to_canonical_biguint(&r_signature_target);
        let s_signature_target =
            circuit_builder.nonnative_to_canonical_biguint(&s_signature_target);
        self.set_biguint_target(&r_signature_target, &signature.r.to_canonical_biguint());
        self.set_biguint_target(&s_signature_target, &signature.s.to_canonical_biguint());
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{secp256k1_scalar::Secp256K1Scalar, types::Sample},
        plonk::{
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_ecdsa::curve::{
        curve_types::{Curve, CurveScalar},
        ecdsa::{sign_message, ECDSASecretKey},
        secp256k1::Secp256K1,
    };

    use crate::circuit::ECDSAIntentCircuit;

    use super::*;

    #[test]
    fn it_works_signature_circuit_verification_with_partial_witness() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let mut pw = PartialWitness::<F>::new();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);

        let ecdsa_targets = builder.verify_intent_signature();
        pw.verify_signed_intent(&mut builder, msg, pk, sig, ecdsa_targets);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).expect("Failed to verify proof data")
    }
}
