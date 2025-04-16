#![allow(non_snake_case)]

use crate::field::{EccPointField, Field};
use crate::scalar::Scalar;
use crate::secp256k1::Secp256k1Point;
use num_bigint::BigUint;
use num_traits::ConstZero;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};

use crate::field::Secp256k1GroupField;

pub type SecretKey = Scalar<Secp256k1GroupField>;
pub type PublicKey = Secp256k1Point;

pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

pub struct Signature {
    pub r_x: Scalar<EccPointField>,
    pub s: Scalar<Secp256k1GroupField>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let prime = Secp256k1GroupField::prime();
        let num = loop {
            let mut bytes = [0u8; 32];
            if OsRng.try_fill_bytes(&mut bytes).is_err() {
                continue;
            }

            let n = BigUint::from_bytes_be(&bytes);
            if n < prime {
                break n;
            }
        };

        let g = Secp256k1Point::generator();
        let sk = Scalar::new(num.clone());
        let pk = sk.clone() * &g;

        Self { sk, pk }
    }

    /**
     * first create the tagged hash of the message. Tag is based on the protocol.
     */

    /// BIP340-compliant signing
    pub fn sign(&self, msg: &[u8], aux_rand: Option<[u8; 32]>) -> Option<Signature> {
        let mut d = self.sk.clone();
        let mut P = self.pk.clone(); // already x-only (even-y)

        if P.y.value.bit(0) {
            d = -d;
            P = -P;
        }

        // ----- Step 1: Auxiliary randomness -----
        let masked_key: [u8; 32] = if let Some(ndata) = aux_rand {
            let mut hasher = Sha256::new();
            hasher.update(b"BIP0340/aux");
            let aux_hash = hasher.finalize();

            let mut hasher = Sha256::new();
            hasher.update(aux_hash);
            hasher.update(aux_hash);
            hasher.update(&ndata);
            hasher.finalize().into()
        } else {
            [
                84, 241, 105, 207, 201, 226, 229, 114, 116, 128, 68, 31, 144, 186, 37, 196, 136,
                244, 97, 199, 11, 94, 165, 220, 170, 247, 175, 105, 39, 10, 165, 20,
            ]
        };

        let t = BigUint::from_bytes_be(&masked_key) ^ &d.value;

        // ----- Step 2: Compute nonce -----
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(&masked_key);
        nonce_input.extend_from_slice(&P.x_only_bytes()); // 32-byte x(P)
        nonce_input.extend_from_slice(msg);

        let mut k = Scalar::tagged_hash(b"BIP0340/nonce", &nonce_input);

        if k.value == BigUint::ZERO {
            return None;
        }

        let mut R = k.clone() * &Secp256k1Point::generator();

        // Ensure even Y for R
        if R.y.value.bit(0) {
            k = -k;
            R = -R;
        }

        let r_x = R.x;

        // ----- Step 3: Challenge scalar -----
        let mut e_input = Vec::new();
        e_input.extend_from_slice(&r_x.value.to_bytes_be());
        e_input.extend_from_slice(&P.x_only_bytes());
        e_input.extend_from_slice(msg);

        let e = Scalar::<Secp256k1GroupField>::tagged_hash(b"BIP0340/challenge", &e_input);

        // ----- Step 4: Signature scalar -----
        let s = k + &(e * &d);

        Some(Signature { r_x, s })
    }
}

impl Signature {
    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> bool {
        let r_x = self.r_x.clone();
        let s = self.s.clone();

        // Compute e = H(r_x || pk_x || msg)
        let mut e_input = Vec::new();
        e_input.extend_from_slice(&r_x.value.to_bytes_be());
        e_input.extend_from_slice(&pk.x_only_bytes());
        e_input.extend_from_slice(msg);

        let e = Scalar::<Secp256k1GroupField>::tagged_hash(b"BIP0340/challenge", &e_input);

        // R = s⋅G - e⋅P
        let sG = s * &Secp256k1Point::generator();
        let eP = e * pk;
        let R = sG - &eP;

        if R.is_infinite() {
            return false;
        }

        !R.y.value.bit(0) && R.x.value == r_x.value
    }
}
