use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::field::Field;
use num_bigint::BigUint;
use num_traits::{Euclid, Num, Zero};
use sha2::{Digest, Sha256};

// Using phantom data to avoid the need to store the prime number for every field element.
// With this definition the sizeof(Scalar) == 256
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar<F: Field> {
    pub(crate) value: BigUint,
    _marker: PhantomData<F>,
}

impl<F: Field + Clone> Scalar<F> {
    pub(crate) fn new(value: BigUint) -> Self {
        let prime = F::prime();
        Self {
            value: value % prime,
            _marker: PhantomData,
        }
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self {
            value: BigUint::from_bytes_be(bytes) % F::prime(),
            _marker: PhantomData,
        }
    }

    pub fn inverse(self) -> Self {
        let prime = F::prime();
        Self::extended_gcd(self.value, prime).1
    }

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

            let temp_x = x0 - &(quotient.clone() * &x1);
            x0 = x1;
            x1 = temp_x;

            let temp_y = y0 - &(quotient * &y1);
            y0 = y1;
            y1 = temp_y;
        }

        (a, x0, y0) // Returns (gcd, x, y)
    }

    pub fn to_hex(&self) -> String {
        format!("{:#x}", self.value)
    }

    pub fn from_hex_str(s: &str) -> Self {
        Self {
            value: BigUint::from_str_radix(s, 16).unwrap(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn tagged_hash(tag: &[u8], bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        let tag_hash = hasher.finalize();

        let mut h = Sha256::new();
        h.update(&tag_hash);
        h.update(&tag_hash); // Tagged hash
        h.update(bytes);
        let num_bytes = h.finalize();

        Scalar::from_bytes_be(&num_bytes)
    }
}

impl<F: Field + Clone> Add<&Scalar<F>> for Scalar<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self::new(self.value + &rhs.value)
    }
}

impl<F: Field + Clone> Sub<&Scalar<F>> for Scalar<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        if self.value > rhs.value {
            Self::new(self.value - &rhs.value)
        } else {
            Self::new(self.value + &(F::prime() - &rhs.value))
        }
    }
}

impl<F: Field + Clone> Div<&Scalar<F>> for Scalar<F> {
    type Output = Self;

    fn div(self, rhs: &Self) -> Self::Output {
        self * &rhs.clone().inverse()
    }
}

impl<F: Field + Clone> Mul<&Scalar<F>> for Scalar<F> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        Self::new(self.value * &rhs.value)
    }
}

impl<F: Field + Clone> Neg for Scalar<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(F::prime() - self.value)
    }
}

impl<F: Field> fmt::Display for Scalar<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;
    use crate::field::{EccPointField, Field};

    #[derive(Debug, Clone, Copy)]
    struct Field7;

    impl Field for Field7 {
        fn prime() -> BigUint {
            BigUint::from_u64(7).unwrap()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Field31;

    impl Field for Field31 {
        fn prime() -> BigUint {
            BigUint::from_u64(31).unwrap()
        }
    }

    #[test]
    fn test_div_jimmy() {
        let a = fe31(3);
        let b = fe31(24);
        assert_eq!(a / &b, fe31(4));

        let a_inv = fe31(17).inverse();
        assert_eq!(a_inv.clone() * &a_inv * &a_inv, fe31(29));

        let a_inv = fe31(4).inverse();
        let b = fe31(11);
        assert_eq!(a_inv.clone() * &a_inv * &a_inv * &a_inv * &b, fe31(13));
    }

    #[test]
    fn test_add_jimmy() {
        let a = fe31(2);
        let b = fe31(14);
        assert_eq!(a + &b, fe31(16));

        let a = fe31(10);
        let b = fe31(26);
        assert_eq!(a + &b, fe31(5));
    }

    // Helper: convert a u64 to a Scalar<Field7> quickly
    fn fe7(x: u64) -> Scalar<Field7> {
        Scalar::<Field7>::new(BigUint::from_u64(x).unwrap())
    }

    // Helper: convert a u64 to a Scalar<Field7> quickly
    fn fe31(x: u64) -> Scalar<Field31> {
        Scalar::<Field31>::new(BigUint::from_u64(x).unwrap())
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

    // #[test]
    // #[should_panic(expected = "Element is not invertible in this field!")]
    // fn test_invert_zero_panics() {
    //     let _ = fe7(0).inverse(); // This should panic
    //     panic!("TODO");
    // }

    #[test]
    fn test_invert() {
        assert_eq!(fe7(3).inverse().value, BigUint::from_u64(5).unwrap()); // 3^-1 ≡ 5 (mod 7)
        assert_eq!(fe7(5).inverse().value, BigUint::from_u64(3).unwrap()); // 5^-1 ≡ 3 (mod 7)
    }

    use proptest::prelude::*;

    fn biguint_256bit_strategy() -> impl Strategy<Value = BigUint> {
        // Generate 32 bytes (256 bits) and convert to BigUint
        prop::array::uniform32(any::<u8>()).prop_map(|bytes| BigUint::from_bytes_be(&bytes))
    }

    proptest! {
        #[test]
        fn inverse_test(x in biguint_256bit_strategy()) {
            let fe: Scalar<EccPointField> = Scalar::new(x);
            prop_assert_eq!(fe.clone() / &fe, Scalar::new(BigUint::from_bytes_be(&[1])))
        }
    }
}
