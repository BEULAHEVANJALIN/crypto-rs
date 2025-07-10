use crate::field::Secp256k1ScalarField;
use crate::scalar::Scalar;
use crate::secp256k1::Secp256k1Point;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

/// A random polynomial f(x) = a0 + a1*x + ... + a_{t-1}*x^{t-1} over the scalar field F_n.
#[derive(Debug, Clone)]
pub struct Poly {
    /// Coefficients a0, a1, ..., a_{t-1}
    pub coeffs: Vec<Scalar<Secp256k1ScalarField>>,
}

impl Poly {
    /// Construct a polynomial from explicit coefficients.
    pub fn from_coeffs(coeffs: Vec<Scalar<Secp256k1ScalarField>>) -> Self {
        Poly { coeffs }
    }

    /// Degree of the polynomial (t-1 if threshold is t).
    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    /// Threshold (number of coefficients).
    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// Generates a random polynomial of degree t-1 (threshold t) using the provided RNG.
    /// Samples 32 random bytes per coefficient, reduces mod n.
    pub fn random<R: RngCore>(t: usize, rng: &mut R) -> Self {
        let mut coeffs = Vec::with_capacity(t);
        for _ in 0..t {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            let v = BigUint::from_bytes_be(&buf);
            coeffs.push(Scalar::new(v));
        }
        Poly { coeffs }
    }

    /// Evaluate the polynomial at x using Horner's method.
    pub fn eval(&self, x: &Scalar<Secp256k1ScalarField>) -> Scalar<Secp256k1ScalarField> {
        let mut result = Scalar::new(BigUint::zero());
        for coeff in self.coeffs.iter().rev() {
            result = result * x + coeff;
        }
        result
    }

    /// Commit to each coefficient by computing G * a_j, yielding EC point commitments.
    #[allow(non_snake_case)]
    pub fn commit(&self) -> Vec<Secp256k1Point> {
        let G = Secp256k1Point::generator();
        self.coeffs.iter().map(|a_j| &G * a_j).collect()
    }

    /// Recover the constant term f(0) from t shares via Lagrange interpolation:
    /// f(0) = sum_{i} y_i * lambda_i, where
    /// lambda_i = prod_{j != i} (-x_j) / (x_i - x_j).
    pub fn interpolate_constant(
        shares: &[(Scalar<Secp256k1ScalarField>, Scalar<Secp256k1ScalarField>)],
    ) -> Scalar<Secp256k1ScalarField> {
        let mut secret = Scalar::new(BigUint::zero());
        for (i, (x_i, y_i)) in shares.iter().enumerate() {
            let mut num = Scalar::new(BigUint::one());
            let mut den = Scalar::new(BigUint::one());
            for (j, (x_j, _)) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = num * &(-x_j.clone());
                den = den * &(x_i.clone() - &x_j.clone());
            }
            let lambda_i = num * &den.inverse();
            secret = secret + &(y_i.clone() * &lambda_i);
        }
        secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    #[allow(non_snake_case)]
    fn poly_eval_and_commit_round_trip() {
        let mut rng = rng();
        let poly = Poly::random(4, &mut rng);
        let commits = poly.commit();
        let G = Secp256k1Point::generator();
        assert_eq!(&G * &poly.coeffs[0], commits[0]);
        let x = Scalar::new(BigUint::from(7u8));
        let y1 = poly.eval(&x);
        let mut x_pow = Scalar::new(BigUint::one());
        let mut y2 = Scalar::new(BigUint::zero());
        for a in &poly.coeffs {
            y2 = y2 + &(a * &x_pow);
            x_pow = x_pow * &x;
        }
        assert_eq!(y1, y2);
    }

    #[test]
    fn interpolate_constant_simple() {
        // f(x) = 3 + 5x + 7x^2 over F_n
        let coeffs = vec![
            Scalar::new(BigUint::from(3u8)),
            Scalar::new(BigUint::from(5u8)),
            Scalar::new(BigUint::from(7u8)),
        ];
        let poly = Poly::from_coeffs(coeffs.clone());
        let points = vec![
            (
                Scalar::new(BigUint::from(1u8)),
                poly.eval(&Scalar::new(BigUint::from(1u8))),
            ),
            (
                Scalar::new(BigUint::from(2u8)),
                poly.eval(&Scalar::new(BigUint::from(2u8))),
            ),
            (
                Scalar::new(BigUint::from(4u8)),
                poly.eval(&Scalar::new(BigUint::from(4u8))),
            ),
        ];
        let secret = Poly::interpolate_constant(&points);
        assert_eq!(secret, coeffs[0]);
    }

    #[test]
    fn interpolate_constant_random() {
        let mut rng = rng();
        let t = 5;
        let poly = Poly::random(t, &mut rng);
        let mut shares = Vec::new();
        for i in 1..=t {
            let x = Scalar::new(BigUint::from(i as u64));
            shares.push((x.clone(), poly.eval(&x)));
        }
        let secret = Poly::interpolate_constant(&shares);
        assert_eq!(secret, poly.coeffs[0]);
    }
}
