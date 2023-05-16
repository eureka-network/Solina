use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::{
    biguint::BigUintTarget,
    curve::CircuitBuilderCurve,
    ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
    nonnative::{CircuitBuilderNonNative, NonNativeTarget},
};

use crate::{C, D, F, FF};

pub trait ECDSAIntentCircuit {
    fn verify_intent_signature(&mut self) -> ECDSASignatureCircuitTargets;
}

pub struct ECDSASignatureCircuitTargets {
    pub(crate) public_key_ecdsa_target: ECDSAPublicKeyTarget<C>,
    pub(crate) message_nonnative_target: NonNativeTarget<FF>,
    pub(crate) signature_ecdsa_signature_target: ECDSASignatureTarget<C>,
}

impl ECDSAIntentCircuit for CircuitBuilder<F, D> {
    fn verify_intent_signature(&mut self) -> ECDSASignatureCircuitTargets {
        let public_key_affine_target = self.add_virtual_affine_point_target::<C>();
        let public_key_ecdsa_target = ECDSAPublicKeyTarget(public_key_affine_target);

        let message_nonnative_target = self.add_virtual_nonnative_target::<FF>();

        let r_ecdsa_nonnative_target = self.add_virtual_nonnative_target::<FF>();
        let s_ecdsa_nonnative_target = self.add_virtual_nonnative_target::<FF>();
        let signature_ecdsa_signature_target = ECDSASignatureTarget {
            r: r_ecdsa_nonnative_target,
            s: s_ecdsa_nonnative_target,
        };

        verify_message_circuit(
            self,
            message_nonnative_target.clone(),
            signature_ecdsa_signature_target.clone(),
            public_key_ecdsa_target.clone(),
        );

        ECDSASignatureCircuitTargets {
            public_key_ecdsa_target,
            message_nonnative_target,
            signature_ecdsa_signature_target,
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{secp256k1_scalar::Secp256K1Scalar, types::Sample},
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_ecdsa::curve::{
        curve_types::{Curve, CurveScalar},
        ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    };

    use super::*;

    #[test]
    fn it_works_signature_circuit_verification() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let pw = PartialWitness::<F>::new();

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg = Secp256K1Scalar::rand();
        let msg_target = builder.constant_nonnative(msg);

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

        let sig = sign_message(msg, sk);

        let ECDSASignature { r, s } = sig;
        let r_target = builder.constant_nonnative(r);
        let s_target = builder.constant_nonnative(s);
        let sig_target: ECDSASignatureTarget<Curve> = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        let ECDSASignatureCircuitTargets {
            public_key_ecdsa_target,
            message_nonnative_target,
            signature_ecdsa_signature_target,
        } = builder.verify_intent_signature();

        builder.connect_affine_point(&public_key_ecdsa_target.0, &pk_target.0);
        builder.connect_nonnative(&sig_target.r, &signature_ecdsa_signature_target.r);
        builder.connect_nonnative(&sig_target.s, &signature_ecdsa_signature_target.s);
        builder.connect_nonnative(&msg_target, &message_nonnative_target);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).expect("Failed to verify proof data")
    }
}
