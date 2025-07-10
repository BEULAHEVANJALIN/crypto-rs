#![allow(non_snake_case)]
use crate::tagged_hash::tagged_hash;
use std::ops::Neg;

use crate::{
    field::{ScalarField, Secp256k1ScalarField},
    secp256k1::{Secp256k1Point, Secp256k1Scalar},
};
use num_bigint::BigUint;

/// BIP-340 keypair: derive x-only public key from secret scalar
pub fn schnorr_pubkey(sk: &Secp256k1Scalar) -> [u8; 32] {
    let g = Secp256k1Point::generator();
    let p = &g * sk; // scalar_mul under the hood
    p.x_only_bytes() // 32-byte big-endian X
}

/// BIP-340 Sign
///
/// - `sk`: secret scalar (0 < sk < n)
/// - `msg`: arbitrary message bytes
/// - `aux`: optional 32-byte auxiliary randomness (if `None`, use zeroes)
///
/// Returns 64-byte `[r_bytes || s_bytes]` Schnorr signature.
pub fn schnorr_sign(sk: &Secp256k1Scalar, msg: &[u8], aux: Option<[u8; 32]>) -> [u8; 64] {
    let g = Secp256k1Point::generator();
    // 1) Compute P = G·d′ and enforce even‐Y
    let mut d = sk.clone();
    let mut P = &g * &d;
    if P.y.to_bytes_be()[31] & 1 == 1 {
        // flip secret and negate point
        let n = Secp256k1ScalarField::order();
        d = Secp256k1Scalar::new(n - d.value());
        P = P.neg();
    }
    let pk_bytes = P.x_only_bytes();

    // 2) Compute nonce t = aux_hash ⊕ sk_bytes
    let aux32 = aux.unwrap_or([0; 32]);
    let aux_hash = tagged_hash("BIP0340/aux", &aux32);
    let sk_bytes = d.to_bytes_be();
    let mut t = [0u8; 32];
    for i in 0..32 {
        t[i] = sk_bytes[i] ^ aux_hash[i];
    }

    // 3) Compute nonce k0 = int(tag_hash("BIP0340/nonce", t||pk||msg)) mod n
    let mut buf = Vec::with_capacity(32 + 32 + msg.len());
    buf.extend(&t);
    buf.extend(&pk_bytes);
    buf.extend(msg);
    let hash_nonce = tagged_hash("BIP0340/nonce", &buf);
    let mut k0 = Secp256k1Scalar::from_bytes_be(&hash_nonce);

    dbg!(
        format!("k0 raw: {:x}", BigUint::from_bytes_be(&hash_nonce)),
        format!("k0 mod n: {}", k0),
    );

    // 4) Compute R = k0*G; if yR is odd, k0 = n – k0, R = –R
    let mut R = &g * &k0;
    let r_y_odd = R.y.to_bytes_be()[31] & 1 == 1;
    if r_y_odd {
        let n = Secp256k1ScalarField::order();
        k0 = Secp256k1Scalar::new(n - k0.value());
        R = R.neg();
    }
    let rx = R.x_only_bytes();

    dbg!(format!("R.x: {:x}", BigUint::from_bytes_be(&rx)), r_y_odd);

    // 5) Compute e = int(tag_hash("BIP0340/challenge", rx||pk||msg)) mod n
    let mut buf2 = Vec::with_capacity(32 + 32 + msg.len());
    buf2.extend(&rx);
    buf2.extend(&pk_bytes);
    buf2.extend(msg);
    let e_bytes = tagged_hash("BIP0340/challenge", &buf2);
    let e = Secp256k1Scalar::from_bytes_be(&e_bytes);

    dbg!(format!("e: {}", e));

    // 6) s = (k0 + e * d) mod n
    let s = k0 + &(e * &d);

    dbg!(format!("s: {}", s));
    // 7) Return [rx || s_bytes]
    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&rx);
    sig[32..64].copy_from_slice(&s.to_bytes_be());
    sig
}

/// BIP-340 Verify
///
/// Returns `true` iff the signature is well-formed and
/// satisfies `sG = R + eP` with correct even-y checks.
pub fn schnorr_verify(pk_bytes: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    // 1) Parse P = lift_x(pk_bytes), reject if failure
    let P = match Secp256k1Point::from_x_only(pk_bytes) {
        Some(pt) => pt,
        None => return false,
    };

    // 2) Split sig
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&sig[0..32]);
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&sig[32..64]);
    let s = Secp256k1Scalar::from_bytes_be(&sb);
    if s.value() >= &Secp256k1ScalarField::order() {
        return false;
    }

    // 3) e = int(tag_hash("BIP0340/challenge", rx||pk||msg)) mod n
    let mut buf = Vec::with_capacity(32 + 32 + msg.len());
    buf.extend(&rx);
    buf.extend(pk_bytes);
    buf.extend(msg);
    let e_bytes = tagged_hash("BIP0340/challenge", &buf);
    let e = Secp256k1Scalar::from_bytes_be(&e_bytes);

    // 4) Compute R' = sG − eP
    let g = Secp256k1Point::generator();
    let Rprime = &g * &s - &(P.clone() * &e);

    // 5) Check R' != inf, y even, x == rx
    if Rprime.infinite {
        return false;
    }
    if Rprime.y.to_bytes_be()[31] & 1 == 1 {
        return false;
    }
    if Rprime.x_only_bytes() != rx {
        return false;
    }
    true
}
