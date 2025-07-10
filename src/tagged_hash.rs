//! Domain-separated, tagged hashing utilities for FROST and Schnorr (BIP-340).
//! Implements the IETF "tagged hash" construction:
//! Hash(tag||tag||msg) with a SHA-256-based domain separator.

use crate::field::{ScalarField, Secp256k1ScalarField};
use crate::scalar::Scalar;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// Compute a 32-byte tagged hash: H = SHA256(SHA256(tag)||SHA256(tag)||msg).
/// This provides domain separation per BIP-340 and RFC 9380 style.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    // 1. Hash the tag itself
    let tag_hash = Sha256::digest(tag.as_bytes());
    // 2. Initialize and feed tag_hash twice, then the message
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(msg);
    // 3. Finalize
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash `msg` under `tag` to a scalar in [0, n-1] by reducing mod the curve order.
pub fn hash_to_scalar(tag: &str, msg: &[u8]) -> Scalar<Secp256k1ScalarField> {
    let h = tagged_hash(tag, msg);
    let x = BigUint::from_bytes_be(&h);
    let r = x % Secp256k1ScalarField::order();
    Scalar::new(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_hash_consistency() {
        let tag = "TESTTAG";
        let msg = b"hello world";
        let h1 = tagged_hash(tag, msg);
        let h2 = tagged_hash(tag, msg);
        assert_eq!(h1, h2, "Tagged hash must be deterministic");

        let h3 = tagged_hash("OTHERTAG", msg);
        assert_ne!(h1, h3, "Different tags produce different hashes");

        let h4 = tagged_hash(tag, b"other message");
        assert_ne!(h1, h4, "Different messages produce different hashes");
    }

    #[test]
    fn hash_to_scalar_range() {
        let tag = "SCALARTEST";
        // empty message
        let s = hash_to_scalar(tag, &[]);
        // scalar must be < order
        assert!(s.value() < &Secp256k1ScalarField::order());
        // hashing same gives same
        let s2 = hash_to_scalar(tag, &[]);
        assert_eq!(s, s2);
    }
}
