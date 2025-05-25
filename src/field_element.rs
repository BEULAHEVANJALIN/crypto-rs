// base field arithmetic for prime fields
use crate::field::Field;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::marker::PhantomData;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Field element in F_p, where F: Field defines prime()=p
/// Used for curve point coordinates (x, y),
/// and all the operations in your Point<F> implementation (point doubling, addition, lift_x, etc.)
/// Modulus = p, the prime of the curve’s base field (for secp256k1:p = 2²⁵⁶ – 2³² – 977)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldElement<F: Field> {
    pub value: BigUint,
    _marker: PhantomData<F>,
}

impl<F: Field> FieldElement<F> {
    // new field element, reducing modulo p
    pub fn new(v: BigUint) -> Self {
        let p = F::prime();
        FieldElement {
            value: v % &p,
            _marker: PhantomData,
        }
    }

    // zero element
    pub fn zero() -> Self {
        FieldElement {
            value: BigUint::zero(),
            _marker: PhantomData,
        }
    }

    // one element
    pub fn one() -> Self {
        FieldElement {
            value: BigUint::one(),
            _marker: PhantomData,
        }
    }

    // serialize to 32-byte big-endian
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        let bytes = self.value.to_bytes_be();
        buf[32 - bytes.len()..].copy_from_slice(&bytes);
        buf
    }

    // parse from 32-byte big-endian
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        FieldElement::new(BigUint::from_bytes_be(bytes))
    }

    // multiplicative inverse via exponentiation (p is prime)
    pub fn inverse(&self) -> Self {
        let p = F::prime();
        assert!(!self.value.is_zero(), "Cannot invert zero");
        // Fermat: a^(p-2) mod p
        let exp = &p - BigUint::from(2u8);
        let inv = self.value.modpow(&exp, &p);
        FieldElement::new(inv)
    }
}

// Arithmetic operations
impl<F: Field> Add for FieldElement<F> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let p = F::prime();
        FieldElement::new((self.value + rhs.value) % &p)
    }
}

impl<F: Field> Sub for FieldElement<F> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let p = F::prime();
        let v = if self.value >= rhs.value {
            self.value - rhs.value
        } else {
            (&self.value + &p) - rhs.value
        };
        FieldElement::new(v % &p)
    }
}

impl<F: Field> Mul for FieldElement<F> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let p = F::prime();
        FieldElement::new((self.value * rhs.value) % &p)
    }
}

impl<F: Field> Neg for FieldElement<F> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        let p = F::prime();
        if self.value.is_zero() {
            self
        } else {
            FieldElement::new((p.clone() - self.value) % &p)
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<F: Field> Div for FieldElement<F> {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}
