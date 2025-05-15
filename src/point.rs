use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use crate::{field::Field, scalar::Scalar};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Num, Zero};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point<T: Field> {
    pub x: Scalar<T>,
    pub y: Scalar<T>,
    pub infinite: bool,
}

impl<T: Field + Clone + PartialEq> Point<T> {
    pub fn identity() -> Self {
        Self::infinity()
    }

    pub fn new(x: BigUint, y: BigUint, infinite: bool) -> Self {
        if infinite {
            return Self::infinity();
        }
        let p = T::prime();
        let lhs = (&y * &y) % &p;                                 // y² mod p
        let rhs = (&x * &x * &x + T::a() * &x + T::b()) % &p;      // (x³ + A·x + B) mod p
        if lhs != rhs {
            panic!("Point ({}, {}) is not on the curve", x, y);
        }
        Self {
            x: Scalar::new(x),
            y: Scalar::new(y),
            infinite,
        }
    }

    pub fn from_hex_xy(x: &str, y: &str) -> Self {
        Self::new(
            BigUint::from_str_radix(x, 16).unwrap(),
            BigUint::from_str_radix(y, 16).unwrap(),
            false,
        )
    }

    /// Returns the point at infinity (identity element).
    pub fn infinity() -> Self {
        Self {
            x: Scalar::new(BigUint::ZERO),
            y: Scalar::new(BigUint::ZERO),
            infinite: true,
        }
    }

    /// Check if the point is at infinity.
    pub fn is_infinite(&self) -> bool {
        self.infinite
    }

    /// Point doubling: P + P
    pub fn double(&self) -> Self {
        if self.is_infinite() {
            return self.clone();
        }
        // If y = 0, then the tangent is vertical, so return the identity element
        if self.y == Scalar::new(BigUint::ZERO) {
            return Self::infinity();
        }

        let x_sq = self.x.clone() * &self.x;

        let three_x_sq = x_sq.clone() + &x_sq + &x_sq;
        let two_y = self.y.clone() + &self.y;
        let two_x = self.x.clone() + &self.x;

        let s = three_x_sq / &two_y;
        let x = s.clone() * &s - &two_x;
        let y = s * &(self.x.clone() - &x) - &self.y;

        Self {
            x,
            y,
            infinite: false,
        }
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        if self.infinite {
            panic!("cannot serialize infinity");
        }
        let mut out = [0u8; 33];
        // prefix: 0x02 if y even, 0x03 if y odd
        out[0] = if (self.y.value.clone() & BigUint::from(1u8)).is_zero() {
            0x02
        } else {
            0x03
        };
        let xb = self.x.value.to_bytes_be();
        let start = 33 - xb.len();
        out[start..].copy_from_slice(&xb);
        out
    }
}

impl<T: Field + PartialEq + Clone> Add<&Point<T>> for Point<T> {
    type Output = Self;

    fn add(self, other: &Self) -> Self::Output {
        if self.is_infinite() {
            return other.clone();
        }
        if other.is_infinite() {
            return self;
        }

        // If x1 == x2 and y1 != y2, return the point at infinity
        if self.x == other.x && self.y != other.y {
            return Self::infinity();
        }

        // If x1 != x2, compute slope `s = (y2 - y1) / (x2 - x1)`
        if self.x != other.x {
            let s = (other.y.clone() - &self.y) / &(other.x.clone() - &self.x);
            let x = s.clone() * &s - &self.x - &other.x;
            let y = s * &(self.x - &x) - &self.y;
            return Self {
                x,
                y,
                infinite: false,
            };
        }

        // Otherwise, it's point doubling
        self.double()
    }
}

impl<T: Field + PartialEq + Clone> Sub<&Point<T>> for Point<T> {
    type Output = Self;

    fn sub(self, other: &Self) -> Self::Output {
        self + &(-other.clone())
    }
}

impl<T: Field + PartialEq + Clone> Neg for Point<T> {
    type Output = Self;
    fn neg(self) -> Self {
        if self.infinite {
            self
        } else {
            Self {
                x: self.x,
                y: -self.y,
                infinite: false,
            }
        }
    }
}

impl<T: Field + PartialEq + Clone> Neg for &Point<T> {
    type Output = Point<T>;
    fn neg(self) -> Point<T> {
        if self.infinite {
            self.clone()
        } else {
            Point {
                x: self.x.clone(),
                y: -self.y.clone(),
                infinite: false,
            }
        }
    }
}

impl<T: Field + PartialEq + Clone, F: Field + PartialEq + Clone> Mul<&Point<T>> for Scalar<F> {
    type Output = Point<T>;

    fn mul(self, rhs: &Point<T>) -> Self::Output {
        let mut current = rhs.clone();
        let mut result = Point::<T>::infinity();
        let mut k = self.value;

        while k > BigUint::ZERO {
            if k.bit(0) {
                result = result + &current;
            }
            current = current.double();
            k = k >> 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Field223;

    impl Field for Field223 {
        fn prime() -> BigUint {
            BigUint::from_u64(223).unwrap()
        }

        fn a() -> BigUint {
            BigUint::zero() // y² = x³ + 0·x + 7  over F₃₃
        }

        fn b() -> BigUint {
            BigUint::from_u64(7).unwrap()
        }
    }

    use std::panic::catch_unwind;

    #[test]
    fn test_on_curve() {
        let valid_points = vec![(192, 105), (17, 56), (1, 193)];
        let invalid_points = vec![(200, 119), (42, 99)];

        for (x, y) in valid_points {
            let p: Point<Field223> = Point::new(
                BigUint::from_u64(x).unwrap(),
                BigUint::from_u64(y).unwrap(),
                false,
            );
            dbg!(p);
        }

        for (x, y) in invalid_points {
            let res = catch_unwind(|| {
                let p: Point<Field223> = Point::new(
                    BigUint::from_u64(x).unwrap(),
                    BigUint::from_u64(y).unwrap(),
                    false,
                );
                dbg!(p);
            });
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_add() {
        let additions = vec![
            // (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        ];
        for (x1, y1, x2, y2, x3, y3) in additions {
            let a: Point<Field223> = Point::new(
                BigUint::from_u64(x1).unwrap(),
                BigUint::from_u64(y1).unwrap(),
                false,
            );
            let b: Point<Field223> = Point::new(
                BigUint::from_u64(x2).unwrap(),
                BigUint::from_u64(y2).unwrap(),
                false,
            );
            let c: Point<Field223> = Point::new(
                BigUint::from_u64(x3).unwrap(),
                BigUint::from_u64(y3).unwrap(),
                false,
            );
            assert_eq!(a + &b, c);
        }
    }

    #[test]
    fn test_scalar_mul() {
        let multiplications: Vec<(u8, u64, u64, u64, u64)> = vec![
            // (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
        ];
        for (c, x1, y1, x2, y2) in multiplications {
            let a: Point<Field223> = Point::new(
                BigUint::from_u64(x1).unwrap(),
                BigUint::from_u64(y1).unwrap(),
                false,
            );
            let b: Point<Field223> = Point::new(
                BigUint::from_u64(x2).unwrap(),
                BigUint::from_u64(y2).unwrap(),
                false,
            );
            assert_eq!(Scalar::<Field223>::from_bytes_be(&[c]) * &a, b);
        }
        let c = Scalar::<Field223>::from_bytes_be(&[21]);
        let a: Point<Field223> = Point::new(
            BigUint::from_u64(47).unwrap(),
            BigUint::from_u64(71).unwrap(),
            false,
        );
        assert_eq!(c * &a, Point::infinity());
    }

    #[test]
    fn test_neg() {
        let a: Point<Field223> = Point::new(
            BigUint::from_u64(47).unwrap(),
            BigUint::from_u64(71).unwrap(),
            false,
        );
        // y_neg = -y mod p = (p - y) % p
        let p = Field223::prime();
        let y_neg = &p - BigUint::from_u64(71).unwrap();
        let neg_a: Point<Field223> = Point::new(BigUint::from_u64(47).unwrap(), y_neg, false);
        assert_eq!(-&a, neg_a);
    }
}
