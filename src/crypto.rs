#[cfg(test)]
mod tests {

    // use super::*;

    use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
    use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
    use core::ops::Mul;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn test_crypto_bls() {
        const DOMAIN: [u8; 12] = [5u8; 12];

        // let g1 = bls12_381::G1Affine::generator();
        let g2 = bls12_381::G2Affine::generator();

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let mut secret_array = [Scalar::zero(); 1];

        Scalar::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(&key, &DOMAIN, &mut secret_array);

        let secret_key = secret_array[0];
        let public_key: G2Affine = g2.clone().clone().mul(secret_key).into();

        let msg = b"Hello";
        let g1_msg_proj =
            <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
                &msg, &DOMAIN,
            );
        let hash_msg = G1Affine::from(g1_msg_proj);
        let sig: G1Affine = hash_msg.clone().mul(secret_key).into();

        let lhs = pairing(&sig, &g2);
        let rhs = pairing(&hash_msg, &public_key);

        assert_eq!(lhs, rhs);
    }
}
