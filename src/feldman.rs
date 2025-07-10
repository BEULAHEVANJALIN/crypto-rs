// src/feldman.rs

use crate::field::Secp256k1ScalarField;
use crate::polynomial::Poly;
use crate::scalar::Scalar;
use crate::secp256k1::Secp256k1Point;
use num_bigint::BigUint;

/// A Feldman Verifiable Secret Sharing (VSS) share for participant `index`.
#[derive(Debug, Clone)]
pub struct FeldmanShare {
    /// Public commitments [g^{a0}, g^{a1}, ..., g^{a_{t-1}}]
    pub commitments: Vec<Secp256k1Point>,
    /// The secret share f(index)
    pub share: Scalar<Secp256k1ScalarField>,
    /// The participant index (1-based)
    pub index: usize,
}

impl FeldmanShare {
    /// Create a FeldmanShare for a dealer's polynomial at `index`.
    pub fn new(commitments: Vec<Secp256k1Point>, poly: &Poly, index: usize) -> Self {
        let x = Scalar::new(BigUint::from(index as u64));
        let share = poly.eval(&x);
        FeldmanShare {
            commitments,
            share,
            index,
        }
    }

    /// Verify that g^{share} == \prod_{j=0..t-1} commitments[j]^{index^j}
    #[allow(non_snake_case)]
    pub fn verify(&self) -> bool {
        // Compute lhs = G * share
        let G = Secp256k1Point::generator();
        let lhs = &G * &self.share;

        // Compute rhs = \sum_j commitments[j] * (index^j)
        let mut rhs = Secp256k1Point::infinity();
        for (j, Cj) in self.commitments.iter().enumerate() {
            // exponent = index^j mod n
            let exp = BigUint::from(self.index as u64).pow(j as u32);
            let exp_scalar = Scalar::new(exp);
            // term = Cj * exp_scalar
            let term = Cj * &exp_scalar;
            rhs = rhs.add_point(&term);
        }

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    fn feldman_new_and_verify() {
        let mut rng = rng();
        let threshold = 3;
        // Dealer constructs a random polynomial f of degree t-1
        let poly = Poly::random(threshold, &mut rng);
        let commits = poly.commit();

        // Create shares for indices 1..=threshold
        let shares: Vec<FeldmanShare> = (1..=threshold)
            .map(|i| FeldmanShare::new(commits.clone(), &poly, i))
            .collect();

        // Each share should verify
        for fs in &shares {
            assert!(fs.verify(), "Share for index {} failed", fs.index);
        }

        // Tamper one share's value
        let mut bad = shares[0].clone();
        bad.share = Scalar::new(BigUint::from(42u8));
        assert!(!bad.verify(), "Tampered share should not verify");
    }

    #[test]
    fn combine_shares_recovers_secret() {
        let mut rng = rng();
        let threshold = 4;
        let poly = Poly::random(threshold, &mut rng);
        let commits = poly.commit();

        // Collect t shares
        let points: Vec<(Scalar<Secp256k1ScalarField>, Scalar<Secp256k1ScalarField>)> = (1
            ..=threshold)
            .map(|i| {
                let fs = FeldmanShare::new(commits.clone(), &poly, i);
                (Scalar::new(BigUint::from(i as u64)), fs.share)
            })
            .collect();

        // Use Poly::interpolate_constant to recover f(0)
        let recovered = Poly::interpolate_constant(&points);
        assert_eq!(recovered, poly.coeffs[0]);
    }
}
