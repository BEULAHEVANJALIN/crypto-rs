//! Schnorr-style proof of discrete logarithm knowledge.
//!
//! Proves knowledge of secret x such that H = x·G under generator G.

use crate::field::{ScalarField, Secp256k1ScalarField};
use crate::secp256k1::{Secp256k1Point, Secp256k1Scalar};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A proof of knowledge of discrete log: R = k·G, μ = k + c·x
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct DlProof {
    /// Commitment point R = k·G
    pub R: Secp256k1Point,
    /// Response μ = k + c·x mod n
    pub mu: Secp256k1Scalar,
}

/// Create a Schnorr proof of knowledge of x for H = x·G.
///
/// # Arguments
/// * `label` - context string for domain separation
/// * `x`     - secret scalar (private key share or polynomial constant)
/// * `rng`   - random source for nonce generation
///
/// # Returns
/// `(proof, H)` where `H = x·G` is the public point.
#[allow(non_snake_case)]
pub fn prove_dl<R: RngCore>(
    label: &[u8],
    x: &Secp256k1Scalar,
    rng: &mut R,
) -> (DlProof, Secp256k1Point) {
    // Generator
    let G = Secp256k1Point::generator();
    // Public value H = x·G
    let H = &G * x;

    // Sample random nonce k
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    let k0 = BigUint::from_bytes_be(&buf) % Secp256k1ScalarField::order();
    let k = Secp256k1Scalar::new(k0.clone());

    // Commitment R = k·G
    let R = &G * &k;

    // Compute challenge c = Hash(label || R.x || H.x) mod n
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(&R.x_only_bytes());
    hasher.update(&H.x_only_bytes());
    let c = BigUint::from_bytes_be(&hasher.finalize()) % Secp256k1ScalarField::order();

    // Response mu = k + c·x (mod n)
    let mut mu_big = c * x.value().clone();
    mu_big += k0;
    mu_big %= Secp256k1ScalarField::order();
    let mu = Secp256k1Scalar::new(mu_big);

    (DlProof { R, mu }, H)
}

/// Verify a Schnorr discrete-log proof.
///
/// Checks that μ·G == R + c·H with c = Hash(label || R.x || H.x).
#[allow(non_snake_case)]
pub fn verify_dl(label: &[u8], proof: &DlProof, H: &Secp256k1Point) -> bool {
    let G = Secp256k1Point::generator();

    // Recompute c = Hash(...) mod n
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(&proof.R.x_only_bytes());
    hasher.update(&H.x_only_bytes());
    let c = BigUint::from_bytes_be(&hasher.finalize()) % Secp256k1ScalarField::order();

    // μ·G
    let muG = &G * &proof.mu;
    // c·H
    let c_scalar = Secp256k1Scalar::new(c);
    let cH = H * &c_scalar;

    // Check μG == R + cH
    muG == proof.R.add_point(&cH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1::Secp256k1Scalar;
    use rand::rng;
    use std::ops::Neg;

    #[test]
    #[allow(non_snake_case)]
    fn dl_proof_round_trip() {
        let mut rng = rng();
        // sample random secret x
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let x = Secp256k1Scalar::new(BigUint::from_bytes_be(&buf));

        let (proof, H) = prove_dl(b"DL-Proof", &x, &mut rng);
        assert!(verify_dl(b"DL-Proof", &proof, &H));

        // wrong label should fail
        assert!(!verify_dl(b"BadLabel", &proof, &H));

        // tamper proof.mu should fail
        let mut bad = proof.clone();
        bad.mu = Secp256k1Scalar::new(BigUint::from(1u8));
        assert!(!verify_dl(b"DL-Proof", &bad, &H));

        // tamper H should fail
        let badH = H.neg();
        assert!(!verify_dl(b"DL-Proof", &proof, &badH));
    }
}
