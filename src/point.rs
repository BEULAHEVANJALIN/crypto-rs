#![allow(non_snake_case)]
use crate::field::Field;
use crate::field_element::FieldElement;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use std::ops::{Add, Mul, Neg, Sub};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point<F: Field> {
    pub x: FieldElement<F>,
    pub y: FieldElement<F>,
    pub infinite: bool,
}

impl<F: Field + Clone + PartialEq> Point<F> {
    /// Point at infinity
    pub fn infinity() -> Self {
        Point {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinite: true,
        }
    }

    /// Identity alias
    pub fn identity() -> Self {
        Self::infinity()
    }

    /// Construct a point, checking curve eq y² = x³ + A·x + B mod p
    pub fn new(x: BigUint, y: BigUint, infinite: bool) -> Self {
        if infinite {
            return Self::infinity();
        }
        let x_fe = FieldElement::new(x);
        let y_fe = FieldElement::new(y);
        // y^2
        let lhs = y_fe.clone() * y_fe.clone();
        // x^3 + A*x + B
        let rhs = x_fe.clone() * x_fe.clone() * x_fe.clone()
            + FieldElement::new(F::a() * &x_fe.value)
            + FieldElement::new(F::b());
        if lhs != rhs {
            panic!("Point not on curve");
        }
        Point {
            x: x_fe,
            y: y_fe,
            infinite: false,
        }
    }

    /// Double the point
    pub fn double(&self) -> Self {
        if self.infinite {
            return self.clone();
        }
        if self.y.value.is_zero() {
            return Self::infinity();
        }
        let two = BigUint::from(2u8);
        let three = BigUint::from(3u8);
        let x_sq = self.x.clone() * self.x.clone();
        let num = FieldElement::new(three * x_sq.value.clone()); // 3x²
        let den = FieldElement::new(two * self.y.value.clone()); // 2y
        let s = num / den;
        let x3 = s.clone() * s.clone() - self.x.clone() - self.x.clone();
        let y3 = s * (self.x.clone() - x3.clone()) - self.y.clone();
        Point {
            x: x3,
            y: y3,
            infinite: false,
        }
    }

    /// Add two points
    pub fn add_point(&self, other: &Self) -> Self {
        if self.infinite {
            return other.clone();
        }
        if other.infinite {
            return self.clone();
        }
        if self.x == other.x && self.y != other.y {
            return Self::infinity();
        }
        if self.x != other.x {
            let num = other.y.clone() - self.y.clone();
            let den = other.x.clone() - self.x.clone();
            let s = num / den;
            let x3 = s.clone() * s.clone() - self.x.clone() - other.x.clone();
            let y3 = s * (self.x.clone() - x3.clone()) - self.y.clone();
            return Point {
                x: x3,
                y: y3,
                infinite: false,
            };
        }
        // same x => doubling
        self.double()
    }

    /// Scalar multiplication using double-and-add
    pub fn scalar_mul(&self, scalar: &BigUint) -> Self {
        let mut result = Self::infinity();
        let mut addend = self.clone();
        let mut k = scalar.clone();
        while k > BigUint::zero() {
            if &k & BigUint::one() == BigUint::one() {
                result = result.add_point(&addend);
            }
            addend = addend.double();
            k >>= 1;
        }
        result
    }

    /// Given a 32-byte big-endian X, attempt to lift into (x,y) with y even.
    pub fn from_x_only(bytes: &[u8; 32]) -> Option<Self> {
        let x = BigUint::from_bytes_be(bytes);
        let p = F::prime();
        if x >= p {
            return None;
        }
        let x3 = (&x * &x * &x + F::a() * &x + F::b()) % &p;
        // compute y = x3^((p+1)/4) mod p  (since p ≡ 3 mod 4)
        let exp = (&p + BigUint::one()) >> 2;
        let y0 = x3.modpow(&exp, &p);
        if (&y0 * &y0) % &p != x3 {
            return None;
        }
        let y = if y0.is_even() { y0.clone() } else { &p - &y0 };
        Some(Point::new(x, y, false))
    }

    /// Returns true if the y-coordinate is odd
    pub fn y_is_odd(&self) -> bool {
        !self.y.value.is_even()
    }

    /// Parse a 33-byte SEC1 compressed point (0x02=even-y, 0x03=odd-y)
    pub fn from_bytes_compressed(bytes: &[u8; 33]) -> Option<Self> {
        let prefix = bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return None;
        }
        // copy the 32-byte X coordinate
        let mut xb = [0u8; 32];
        xb.copy_from_slice(&bytes[1..33]);

        // recover the even-Y solution (or None if x is not on the curve)
        let mut P = Point::from_x_only(&xb)?;

        // if prefix==0x03, flip to the odd-Y root
        if prefix == 0x03 {
            P.y = -P.y;
        }
        Some(P)
    }

    /// 33-byte SEC1 compressed encoding: 0x02 if y even, 0x03 if y odd, followed by big-endian x
    pub fn to_bytes_compressed(&self) -> [u8; 33] {
        assert!(!self.infinite, "cannot serialize the point at infinity");
        let mut out = [0u8; 33];
        out[0] = if self.y.value.is_even() { 0x02 } else { 0x03 };
        // get x in big-endian, then pad on the left
        let xb = self.x.value.to_bytes_be();
        if xb.len() > 32 {
            panic!("x coordinate is too large");
        }
        let pad = 32 - xb.len();
        // fill the padding zeros (this loop is optional since out is already zeroed)
        for i in 0..pad {
            out[1 + i] = 0;
        }
        out[1 + pad..33].copy_from_slice(&xb);
        out
    }
}

impl<F: Field + Clone + PartialEq> Add<&Point<F>> for Point<F> {
    type Output = Point<F>;
    fn add(self, rhs: &Point<F>) -> Self::Output {
        self.add_point(rhs)
    }
}

impl<F: Field + Clone + PartialEq> Sub<&Point<F>> for Point<F> {
    type Output = Point<F>;
    fn sub(self, rhs: &Point<F>) -> Self::Output {
        if rhs.infinite {
            return self;
        }
        let neg_rhs = Point {
            x: rhs.x.clone(),
            y: rhs.y.clone().neg(),
            infinite: false,
        };
        self.add_point(&neg_rhs)
    }
}

impl<F: Field + Clone + PartialEq> Neg for Point<F> {
    type Output = Point<F>;
    fn neg(self) -> Self::Output {
        if self.infinite {
            self
        } else {
            Point {
                x: self.x,
                y: self.y.neg(),
                infinite: false,
            }
        }
    }
}

// Allow &Point * &BigUint
impl<F: Field + Clone + PartialEq> Mul<&BigUint> for &Point<F> {
    type Output = Point<F>;
    fn mul(self, rhs: &BigUint) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

// Allow owned Point * &BigUint
impl<F: Field + Clone + PartialEq> Mul<&BigUint> for Point<F> {
    type Output = Point<F>;
    fn mul(self, rhs: &BigUint) -> Self::Output {
        self.scalar_mul(rhs)
    }
}

#[cfg(test)]
mod tests {

    use num_traits::FromPrimitive;

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
        let valid = vec![(192, 105), (17, 56), (1, 193)];
        for (x, y) in valid {
            let _ = Point::<Field223>::new(
                BigUint::from_u64(x).unwrap(),
                BigUint::from_u64(y).unwrap(),
                false,
            );
        }
        let invalid = vec![(200, 119), (42, 99)];
        for (x, y) in invalid {
            let res = catch_unwind(|| {
                Point::<Field223>::new(
                    BigUint::from_u64(x).unwrap(),
                    BigUint::from_u64(y).unwrap(),
                    false,
                )
            });
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_add() {
        let tests = vec![
            (192, 105, 17, 56, 170, 142),
            (47, 71, 117, 141, 60, 139),
            (143, 98, 76, 66, 47, 71),
        ];
        for (x1, y1, x2, y2, x3, y3) in tests {
            let a = Point::<Field223>::new(
                BigUint::from_u64(x1).unwrap(),
                BigUint::from_u64(y1).unwrap(),
                false,
            );
            let b = Point::<Field223>::new(
                BigUint::from_u64(x2).unwrap(),
                BigUint::from_u64(y2).unwrap(),
                false,
            );
            let c = Point::<Field223>::new(
                BigUint::from_u64(x3).unwrap(),
                BigUint::from_u64(y3).unwrap(),
                false,
            );
            assert_eq!(a.clone() + &b, c);
        }
    }

    #[test]
    fn test_double() {
        // doubling same as add P+P
        let p = Point::<Field223>::new(
            BigUint::from_u64(192).unwrap(),
            BigUint::from_u64(105).unwrap(),
            false,
        );
        let doubled = p.double();
        let added = p.clone().add_point(&p);
        assert_eq!(doubled, added);
    }

    #[test]
    fn test_scalar_mul() {
        let a = Point::<Field223>::new(
            BigUint::from_u64(47).unwrap(),
            BigUint::from_u64(71).unwrap(),
            false,
        );
        // 2*A
        let two = BigUint::from_u64(2).unwrap();
        let a2 = a.clone().scalar_mul(&two);
        assert_eq!(
            a2,
            Point::<Field223>::new(
                BigUint::from_u64(36).unwrap(),
                BigUint::from_u64(111).unwrap(),
                false
            )
        );
        // 0*A = infinity
        let zero = BigUint::zero();
        assert_eq!(a.scalar_mul(&zero), Point::<Field223>::infinity());
    }

    #[test]
    fn test_neg() {
        let a = Point::<Field223>::new(
            BigUint::from_u64(47).unwrap(),
            BigUint::from_u64(71).unwrap(),
            false,
        );
        let p = BigUint::from_u64(223).unwrap();
        let y_neg = (&p - BigUint::from_u64(71).unwrap()) % &p;
        let neg_a = Point::<Field223>::new(BigUint::from_u64(47).unwrap(), y_neg, false);
        assert_eq!(-a, neg_a);
    }

    #[test]
    fn test_compress() {
        let G = Point::generator();
        let bytes = G.to_bytes_compressed();
        assert_eq!(bytes[0], 0x02); // G’s y is even
        let G1 = Point::from_bytes_compressed(&bytes).unwrap();
        assert_eq!(G1, G);
    }
}
