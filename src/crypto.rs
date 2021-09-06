use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField};
use bls12_381::{G2Affine, Scalar};
use core::ops::Mul;
use rand::rngs::OsRng;
use rand::RngCore;

use bls12_381::{pairing, G1Affine, G1Projective};

pub type PublicKey = G2Affine;
pub type SecretKey = Scalar;
pub type Signature = [u8; 48];

const DOMAIN: [u8; 12] = [5u8; 12];

pub fn key_gen() -> (PublicKey, SecretKey) {
    let g2 = bls12_381::G2Affine::generator();

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut secret_array = [Scalar::zero(); 1];

    Scalar::hash_to_field::<ExpandMsgXmd<sha2::Sha256>>(&key, &DOMAIN, &mut secret_array);

    let secret_key = secret_array[0];
    let public_key: G2Affine = g2.clone().clone().mul(secret_key).into();
    (public_key, secret_key)
}

pub fn sign(secret_key: &SecretKey, message: &[u8], signature: &mut Signature) {
    let g1_msg_proj = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        &message, &DOMAIN,
    );
    let hash_msg = G1Affine::from(g1_msg_proj);
    let sig: G1Affine = hash_msg.clone().mul(secret_key).into();
    *signature = sig.to_compressed();
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature : &Signature) -> bool {
    let sig_g1 = G1Affine::from_compressed(&signature);
    let g2 = bls12_381::G2Affine::generator();

    if sig_g1.is_none().unwrap_u8() == 1 {
        return false;
    }

    let sig_g1 = sig_g1.unwrap();

    let g1_msg_proj =
        <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
            &message, &DOMAIN,
        );
    let hash_msg = G1Affine::from(g1_msg_proj);

    let lhs = pairing(&sig_g1, &g2);
    let rhs = pairing(&hash_msg, &public_key);

    return lhs == rhs
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_crypto_bls() {
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

    #[test]
    fn test_key_gen() {
        let (public_key, secret_key) = key_gen();

        // let g1 = bls12_381::G1Affine::generator();
        let g2 = bls12_381::G2Affine::generator();

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

    #[test]
    fn test_key_sign() {
        let (public_key, secret_key) = key_gen();

        // let g1 = bls12_381::G1Affine::generator();
        let g2 = bls12_381::G2Affine::generator();

        let mut sig_bytes: Signature = [0; 48];
        sign(&secret_key, b"Hello", &mut sig_bytes);

        let sig = G1Affine::from_compressed(&sig_bytes).unwrap();

        let msg = b"Hello";
        let g1_msg_proj =
            <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
                &msg, &DOMAIN,
            );
        let hash_msg = G1Affine::from(g1_msg_proj);

        let lhs = pairing(&sig, &g2);
        let rhs = pairing(&hash_msg, &public_key);

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_key_verify() {
        let (public_key, secret_key) = key_gen();

        let mut sig_bytes: Signature = [0; 48];
        sign(&secret_key, b"Hello", &mut sig_bytes);

        assert!(verify(&public_key, b"Hello", &sig_bytes));
    }
}
