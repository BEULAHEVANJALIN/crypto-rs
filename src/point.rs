use std::{fmt::Debug, ops::{Add, Mul}};

use crate::{field::PrimeField, field_element::FieldElement};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Num};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point<T: PrimeField> {
    pub x: FieldElement<T>,
    pub y: FieldElement<T>,
    pub infinite: bool,
}

impl <T: PrimeField + Clone + Debug + PartialEq> Point<T> {
    pub fn new(x: BigUint, y: BigUint, infinite: bool) -> Self {
        if infinite {
            return Self::infinity();
        }
        let x = FieldElement::new(x);
        let y = FieldElement::new(y);
        assert_eq!(y.clone() * &y, x.clone() * &x * &x + &FieldElement::new(BigUint::from_u64(7).unwrap()), "Point not on the curve");

        Self {
            x,
            y,
            infinite,
        }
    }

    pub fn from_hex_xy(x: &str, y: &str) -> Self {
        Self::new(BigUint::from_str_radix(x, 16).unwrap(), BigUint::from_str_radix(y, 16).unwrap(),  false )
    }

    /// Returns the point at infinity (identity element).
    pub fn infinity() -> Self {
        Self {
            x: FieldElement::new(BigUint::ZERO),
            y: FieldElement::new(BigUint::ZERO),
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
        if self.y == FieldElement::new(BigUint::ZERO) {
            return Self::infinity();
        }

        let x_sq = self.x.clone() * &self.x;

        let three_x_sq = x_sq.clone() + &x_sq + &x_sq;
        let two_y = self.y.clone() + &self.y;
        let two_x = self.x.clone() + &self.x;

        let s = three_x_sq / &two_y;
        let x = s.clone() * &s - &two_x;
        let y = s * &(self.x.clone() - &x) - &self.y;

        Self { x, y, infinite: false }
    }
}

impl <T: PrimeField + PartialEq + Clone + Debug> Add<&Point<T>> for Point<T> {
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
            return Self { x, y, infinite: false };
        }

        // Otherwise, it's point doubling
        self.double()
    }
}

impl<T: PrimeField + PartialEq + Clone + Debug> Mul<Point<T>> for BigUint {
    type Output = Point<T>;

    fn mul(self, rhs: Point<T>) -> Self::Output {
        let mut current = rhs;
        let mut result = Point::<T>::infinity();
        let mut k = self % T::order();

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

    impl PrimeField for Field223 {
        fn prime() -> BigUint {
            BigUint::from_u64(223).unwrap()
        }
        fn order() -> BigUint {
            BigUint::from_u64(60000).unwrap() // Don't know how to compute, so decided on a bigger value, which won't harm these tests
        }
    }

    use std::panic::catch_unwind;

    #[test]
    fn test_on_curve() {
        let valid_points = vec!((192, 105), (17, 56), (1, 193));
        let invalid_points = vec!((200, 119), (42, 99));

        for (x, y) in valid_points {
            let p: Point<Field223> = Point::new(BigUint::from_u64(x).unwrap(), BigUint::from_u64(y).unwrap(), false);
            dbg!(p);
        }

        for (x, y) in invalid_points {
            let res = catch_unwind(|| {
                let p: Point<Field223> = Point::new(BigUint::from_u64(x).unwrap(), BigUint::from_u64(y).unwrap(), false);
                dbg!(p);
            });
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_add() {
        let additions = vec!(
            // (x1, y1, x2, y2, x3, y3)
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        );
        for (x1, y1, x2, y2, x3, y3) in additions {
            let a: Point<Field223> = Point::new(BigUint::from_u64(x1).unwrap(), BigUint::from_u64(y1).unwrap(), false);
            let b: Point<Field223> = Point::new(BigUint::from_u64(x2).unwrap(), BigUint::from_u64(y2).unwrap(), false);
            let c: Point<Field223> = Point::new(BigUint::from_u64(x3).unwrap(), BigUint::from_u64(y3).unwrap(), false);
            assert_eq!(a + &b, c);
        }
    }

    #[test]
    fn test_scalar_mul() {
        let multiplications = vec!(
            // (coefficient, x1, y1, x2, y2)
            (2, 192, 105, 49, 71),
            (2, 143, 98, 64, 168),
            (2, 47, 71, 36, 111),
            (4, 47, 71, 194, 51),
            (8, 47, 71, 116, 55),
        );
        for (c, x1, y1, x2, y2) in multiplications {
            let a: Point<Field223> = Point::new(BigUint::from_u64(x1).unwrap(), BigUint::from_u64(y1).unwrap(), false);
            let b: Point<Field223> = Point::new(BigUint::from_u64(x2).unwrap(), BigUint::from_u64(y2).unwrap(), false);
            assert_eq!(BigUint::from_u64(c).unwrap() * a, b);
        }
        let c = BigUint::from_u64(21).unwrap();
        let a: Point<Field223> = Point::new(BigUint::from_u64(47).unwrap(), BigUint::from_u64(71).unwrap(), false);
        assert_eq!(c * a, Point::infinity());
    }

}