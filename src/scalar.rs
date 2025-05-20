use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::field::ScalarField;
use num_bigint::BigUint;
use num_traits::{Euclid, One, Zero};
use sha2::{Digest, Sha256};

/// Used for everything that's 'scalar' in the crypto sense:
/// secret keys, nonces, signature scalars (s, e, k), challenge hashes reduced mod n.
/// Modulus = n, the order of the group (for secp256k1:n = 0xFFFFFFFF…4141)
#[derive(Clone, PartialEq, Eq)]
pub struct Scalar<F: ScalarField> {
    pub(crate) value: BigUint,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> Debug for Scalar<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Scalar({:#x})", self.value)
    }
}

impl<F: ScalarField> Scalar<F> {
    /// Construct a scalar reduced modulo the field order
    pub fn new(value: BigUint) -> Self {
        let modulus = F::order();
        Self {
            value: value % &modulus,
            _marker: PhantomData,
        }
    }

    /// Return the raw BigUint value
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Serialize to 32-byte big-endian (mod order)
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        let bytes = self.value.to_bytes_be();
        buf[32 - bytes.len()..].copy_from_slice(&bytes);
        buf
    }

    /// Create from big-endian bytes, reduced mod order
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let num = BigUint::from_bytes_be(bytes);
        Self::new(num)
    }

    /// Compute multiplicative inverse via extended GCD
    pub fn inverse(&self) -> Self {
        let order = F::order();
        let (g, x, _) = Self::extended_gcd(self.value.clone(), order.clone());
        assert!(g.is_one(), "Element not invertible");
        // x may be negative; ensure positive mod order
        let inv = x.value.clone();
        // BigUint is always non-negative, so no sign check is needed
        Scalar::new(inv)
    }

    /// Extended GCD: returns (gcd, x, y) such that ax + by = gcd
    fn extended_gcd(mut a: BigUint, mut b: BigUint) -> (BigUint, Self, Self) {
        let mut x0 = Scalar::new(BigUint::from_bytes_be(&[0x1]));
        let mut x1 = Scalar::new(BigUint::ZERO);
        let mut y0 = Scalar::new(BigUint::ZERO);
        let mut y1 = Scalar::new(BigUint::from_bytes_be(&[0x1]));

        while !b.is_zero() {
            let (quotient, remainder) = a.div_rem_euclid(&b);
            a = b;
            b = remainder;

            let quotient = Scalar::new(quotient);

            let temp_x = x0 - &(&quotient * &x1);
            x0 = x1;
            x1 = temp_x;

            let temp_y = y0 - &(&quotient * &y1);
            y0 = y1;
            y1 = temp_y;
        }

        (a, x0, y0) // Returns (gcd, x, y)
    }

    /// Compute tagged-hash as scalar: SHA256(SHA256(tag)||SHA256(tag)||msg) mod order
    pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> Self {
        let tag_hash = Sha256::digest(tag);
        let mut h = Sha256::new();
        h.update(&tag_hash);
        h.update(&tag_hash);
        h.update(msg);
        let out = h.finalize();
        Scalar::from_bytes_be(&out)
    }
}

impl<F: ScalarField> Add<&Scalar<F>> for Scalar<F> {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        let n = F::order();
        let sum = (self.value + &rhs.value) % &n;
        Scalar::new(sum)
    }
}

impl<F: ScalarField> Sub<&Scalar<F>> for Scalar<F> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        let n = F::order();
        let diff = if self.value >= rhs.value {
            &self.value - &rhs.value
        } else {
            &self.value + &n - &rhs.value
        };
        Scalar::new(diff % &n)
    }
}

impl<F: ScalarField> Mul<&Scalar<F>> for Scalar<F> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self {
        let n = F::order();
        let prod = (self.value * &rhs.value) % &n;
        Scalar::new(prod)
    }
}

impl<F: ScalarField> Mul<&Scalar<F>> for &Scalar<F> {
    type Output = Scalar<F>;
    fn mul(self, rhs: &Scalar<F>) -> Scalar<F> {
        let n = F::order();
        let prod = (&self.value * &rhs.value) % &n;
        Scalar::new(prod)
    }
}

impl<F: ScalarField> Div<&Scalar<F>> for Scalar<F> {
    type Output = Self;
    fn div(self, rhs: &Self) -> Self {
        let inv = rhs.inverse();
        self * &inv
    }
}

impl<F: ScalarField> Neg for Scalar<F> {
    type Output = Self;
    fn neg(self) -> Self {
        let n = F::order();
        if self.value.is_zero() {
            Scalar::new(BigUint::zero())
        } else {
            Scalar::new((&n - &self.value) % &n)
        }
    }
}

impl<F: ScalarField> fmt::Display for Scalar<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::{FromPrimitive, One, Zero};
    use proptest::prelude::*;

    /// A tiny scalar field GF(7)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct F7;
    impl ScalarField for F7 {
        fn order() -> BigUint {
            BigUint::from_u64(7).unwrap()
        }
    }

    /// A slightly larger toy field GF(31)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct F31;
    impl ScalarField for F31 {
        fn order() -> BigUint {
            BigUint::from_u64(31).unwrap()
        }
    }

    // Helpers to build Scalars in those fields:
    fn fe7(x: u64) -> Scalar<F7> {
        Scalar::new(BigUint::from_u64(x).unwrap())
    }
    fn fe31(x: u64) -> Scalar<F31> {
        Scalar::new(BigUint::from_u64(x).unwrap())
    }

    #[test]
    fn test_div_mod31_examples() {
        // 3 / 24 ≡ 4  (since 24*4=96≡3 mod31)
        assert_eq!(fe31(3) / &fe31(24), fe31(4));
        // 17⁻¹ * itself^2 = 29
        let inv17 = fe31(17).inverse();
        assert_eq!(&inv17 * &inv17 * &inv17, fe31(29));
        // 4⁻¹=8, 8^4 * 11 ≡ 13
        let inv4 = fe31(4).inverse();
        assert_eq!(&(&(&inv4 * &inv4) * &inv4) * &inv4 * &fe31(11), fe31(13));
    }

    #[test]
    fn test_add_mod31() {
        // 2 + 14 = 16
        assert_eq!(
            (fe31(2) + &fe31(14)).value(),
            &BigUint::from_u64(16).unwrap()
        );
        // 10 + 26 = 36 ≡ 5
        assert_eq!(
            (fe31(10) + &fe31(26)).value(),
            &BigUint::from_u64(5).unwrap()
        );
    }

    #[test]
    fn test_new_reduces_value() {
        assert_eq!(fe7(8).value, BigUint::from_u64(1).unwrap()); // 8 mod 7 = 1
        assert_eq!(fe7(14).value, BigUint::from_u64(0).unwrap()); // 14 mod 7 = 0
        assert_eq!(fe7(0).value, BigUint::from_u64(0).unwrap()); // 0 mod 7 = 0
    }

    #[test]
    fn test_add() {
        assert_eq!((fe7(3) + &fe7(5)).value, BigUint::from_u64(1).unwrap()); // 3 + 5 = 8 ≡ 1 (mod 7)
        assert_eq!((fe7(6) + &fe7(1)).value, BigUint::from_u64(0).unwrap()); // 6 + 1 = 7 ≡ 0 (mod 7)
    }

    #[test]
    fn test_sub() {
        assert_eq!((fe7(3) - &fe7(5)).value, BigUint::from_u64(5).unwrap()); // 3 - 5 ≡ -2 ≡ 5 (mod 7)
        assert_eq!((fe7(2) - &fe7(2)).value, BigUint::from_u64(0).unwrap()); // 2 - 2 = 0
        assert_eq!((fe7(0) - &fe7(1)).value, BigUint::from_u64(6).unwrap()); // 0 - 1 ≡ -1 ≡ 6 (mod 7)
    }

    #[test]
    fn test_mul() {
        assert_eq!((fe7(3) * &fe7(5)).value, BigUint::from_u64(1).unwrap()); // 3 * 5 = 15 ≡ 1 (mod 7)
        assert_eq!((fe7(6) * &fe7(2)).value, BigUint::from_u64(5).unwrap()); // 6 * 2 = 12 ≡ 5 (mod 7)
    }

    #[test]
    fn test_neg() {
        assert_eq!((-fe7(0)).value, BigUint::from_u64(0).unwrap()); // -0 = 0
        assert_eq!((-fe7(3)).value, BigUint::from_u64(4).unwrap()); // -(3) ≡ -3 ≡ 4 (mod 7)
    }

    #[test]
    fn test_div_mod7() {
        // 6 / 3 = 2
        assert_eq!((fe7(6) / &fe7(3)).value(), &BigUint::from_u64(2).unwrap());
        // 4 / 2 = 2
        assert_eq!((fe7(4) / &fe7(2)).value(), &BigUint::from_u64(2).unwrap());
    }

    #[test]
    #[should_panic(expected = "Element not invertible")]
    fn test_invert_zero_panics() {
        let _ = fe7(0).inverse(); // This should panic
        panic!("Element is not invertible in this field!");
    }

    #[test]
    fn test_inverse_mod7() {
        // 3⁻¹ ≡ 5, 5⁻¹ ≡ 3
        assert_eq!(fe7(3).inverse().value(), &BigUint::from_u64(5).unwrap()); // 3^-1 ≡ 5 (mod 7)
        assert_eq!(fe7(5).inverse().value(), &BigUint::from_u64(3).unwrap()); // 5^-1 ≡ 3 (mod 7)
    }

    fn biguint_256bit_strategy() -> impl Strategy<Value = BigUint> {
        // Generate 32 bytes (256 bits) and convert to BigUint
        prop::array::uniform32(any::<u8>()).prop_map(|bytes| BigUint::from_bytes_be(&bytes))
    }

    proptest! {
        #[test]
        fn prop_inverse_mod31(x in biguint_256bit_strategy()) {
            // For non-zero x mod 31, x/x == 1
            let a = Scalar::<F31>::new(x);
            // Avoid the zero divisor
            prop_assume!(!a.value().is_zero());
            let one = Scalar::<F31>::new(BigUint::one());
            prop_assert_eq!(a.clone() / &a, one);
        }
    }
}
