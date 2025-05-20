// tests/bip340.rs
// BIP-340 test vectors for our Schnorr implementation
use csv::ReaderBuilder;
use hex::FromHex;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::Deserialize;
use std::{fs::File, path::Path};

use crypto_rs::field::{Field, Secp256k1Field};
use crypto_rs::schnorr::{schnorr_verify};
use crypto_rs::secp256k1::{Secp256k1Point, Secp256k1Scalar};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Bip340Record {
    index: usize,
    secret_key: String,
    public_key: String,
    aux_rand: String,
    message: String,
    signature: String,
    verification_result: String,
    comment: String,
}

/// Compute y = sqrt(a) mod p for p ≡ 3 (mod 4)
fn sqrt_mod_p(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        return Some(BigUint::zero());
    }
    let exp = (p + BigUint::one()) >> 2;
    let y = a.modpow(&exp, p);
    if (&y * &y) % p == a % p {
        Some(y)
    } else {
        None
    }
}

/// Lift an x-only coordinate into a full point with even y
fn recover_xonly_point(x: &BigUint) -> Option<Secp256k1Point> {
    let p = Secp256k1Field::prime();
    let a = Secp256k1Field::a();
    let b = Secp256k1Field::b();
    let rhs = (x.modpow(&BigUint::from(3u8), &p) + &a * x + &b) % &p;
    let y0 = sqrt_mod_p(&rhs, &p)?;
    let y = if y0.bit(0) { &p - &y0 } else { y0 };
    Some(Secp256k1Point::new(x.clone(), y, false))
}

#[test]
fn bip340_test_vectors() {
    let path = Path::new("tests/test-vectors.csv");
    let file = File::open(path).expect("cannot open test-vectors.csv");
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

    for result in rdr.deserialize::<Bip340Record>() {
        let row = result.expect("CSV deserialize failed");
        // parse secret key
        let sk_bytes = if row.secret_key.is_empty() {
            None
        } else {
            Some(<[u8; 32]>::from_hex(&row.secret_key).unwrap())
        };
        // parse public x-only
        let pk_bytes: [u8; 32] = <[u8; 32]>::from_hex(&row.public_key).unwrap();
        // parse message
        let msg: Vec<u8> = <Vec<u8>>::from_hex(&row.message).unwrap();
        // parse signature
        let sig: [u8; 64] = <[u8; 64]>::from_hex(&row.signature).unwrap();
        // parse aux
        if row.aux_rand.is_empty() {
            None
        } else {
            Some(<[u8; 32]>::from_hex(&row.aux_rand).unwrap())
        };
        let expect_ok = row.verification_result.eq_ignore_ascii_case("TRUE");

        // verification (give the raw bytes to our library; it will return false if pk is invalid)
        let ok = schnorr_verify(&pk_bytes, &msg, &sig);
        assert_eq!(
            ok, expect_ok,
            "verify mismatch @ {}: {}",
            row.index, row.comment
        );

        // signing test when secret provided
        if let Some(sk_b) = sk_bytes {
            let sk_scalar = Secp256k1Scalar::from_bytes_be(&sk_b);
            // Now that we know pk_bytes is a valid curve point, we can recover it for comparison:
            let pk_point = recover_xonly_point(&BigUint::from_bytes_be(&pk_bytes))
                .expect("pubkey lift failed on a valid vector");
            // Only compare x-only coordinates
            let regen_pk = Secp256k1Point::generator() * &sk_scalar;
            assert_eq!(
                regen_pk.x_only_bytes(),
                pk_point.x_only_bytes(),
                "pubkey x-coordinate mismatch @ {}",
                row.index
            );
        }
    }
}
