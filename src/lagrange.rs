//! Utilities for computing Lagrange interpolation coefficients over the scalar field.

use crate::field::Secp256k1ScalarField;
use crate::scalar::Scalar;
use num_bigint::BigUint;
use std::ops::Neg;

/// Lagrange coefficient λ_i for index `i` given a signing subset `S`.
///
/// # Formula
/// For a set of distinct indices S = {i_1,...,i_t}, the coefficient at i = i_k is
/// ```text
/// λ_i = ∏_{j ∈ S, j ≠ i} (0 - j) / (i - j)  (mod n)
///      = ∏_{j ∈ S, j ≠ i} (-j) * (i - j)^{-1}
/// ```
/// These satisfy ∑_{i ∈ S} λ_i · f(i) = f(0) for any degree-(t-1) polynomial f.
#[allow(non_snake_case)]
pub fn lagrange_coefficient(i: usize, S: &[usize]) -> Scalar<Secp256k1ScalarField> {
    // numerator = ∏_{j != i} (-j)
    let mut num = Scalar::new(BigUint::from(1u8));
    // denominator = ∏_{j != i} (i - j)
    let mut den = Scalar::new(BigUint::from(1u8));
    for &j in S {
        if j == i {
            continue;
        }
        // -j mod n
        let neg_j = Scalar::new(BigUint::from(j as u64)).neg();
        num = num * &neg_j;
        // (i - j) mod n
        let diff = Scalar::new(BigUint::from(i as u64)) - &Scalar::new(BigUint::from(j as u64));
        den = den * &diff;
    }
    // λ_i = num * den^{-1}
    num * &den.inverse()
}

/// Compute all Lagrange coefficients for the set `S`.
/// Returns a vector of (i, λ_i) for each i in S.
#[allow(non_snake_case)]
pub fn lagrange_coefficients(S: &[usize]) -> Vec<(usize, Scalar<Secp256k1ScalarField>)> {
    S.iter().map(|&i| (i, lagrange_coefficient(i, S))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::Scalar;
    use num_bigint::BigUint;
    use num_traits::One;

    #[test]
    #[allow(non_snake_case)]
    fn lagrange_sum_identity() {
        // For S = {1,2,4}, compute λ_i and check that ∑ λ_i · f(i) = f(0)
        // Let f(x) = 3 + 5x + 7x^2 (same poly as test). f(0)=3.
        let f = |x: u64| -> Scalar<Secp256k1ScalarField> {
            let x1 = Scalar::new(BigUint::from(x));
            let x2 = x1.clone() * &x1;
            Scalar::new(BigUint::from(3u8))
                + &(Scalar::new(BigUint::from(5u8)) * &x1)
                + &(Scalar::new(BigUint::from(7u8)) * &x2)
        };
        let S = [1usize, 2, 4];
        let coeffs = lagrange_coefficients(&S);
        // reconstruct f0
        let mut sum = Scalar::new(BigUint::from(0u8));
        for &(i, ref lambda) in &coeffs {
            let yi = f(i as u64);
            sum = sum + &(lambda.clone() * &yi);
        }
        assert_eq!(sum, Scalar::new(BigUint::from(3u8)));
    }

    #[test]
    #[allow(non_snake_case)]
    fn sum_of_lagrange_equals_one() {
        let S = [3usize, 5, 7];
        let coeffs = lagrange_coefficients(&S);
        // ∑ λ_i should equal 1 mod n for interpolation at zero
        let mut sum = Scalar::new(BigUint::from(0u8));
        for &(_, ref lambda) in &coeffs {
            sum = sum + lambda;
        }
        assert_eq!(sum, Scalar::new(BigUint::one()));
    }
}
