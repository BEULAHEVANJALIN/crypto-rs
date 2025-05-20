use num_bigint::BigUint;
use num_traits::{FromPrimitive, Zero};

/// Trait representing an elliptic curve base field (used for `x`, `y` coordinates)
pub trait Field {
    /// The modulus `p` of the field (F_p)
    fn prime() -> BigUint;
    /// Curve coefficient A in the Weierstrass equation: `y² = x³ + A·x + B`
    fn a() -> BigUint;
    /// Curve coefficient B in the Weierstrass equation: `y² = x³ + A·x + B`
    fn b() -> BigUint;
}

/// Trait representing a scalar field (F_n), usually the order of the curve group
pub trait ScalarField {
    /// The order `n` of the group
    fn order() -> BigUint;
}

/// Constants
// Prime field for secp256k1: p = 2^256 - 2^32 - 977
const SECP256K1_P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
// Order of the secp256k1 curve group: n = ...
const SECP256K1_N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

// Generator x-coordinate for secp256k1 (uncompressed, hex string)
pub const SECP256K1_G_X: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
// Generator y-coordinate for secp256k1 (uncompressed, hex string)
pub const SECP256K1_G_Y: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

/// Base‐field for secp256k1: Fp where
///     p = 2^256 − 2^32 − 977
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1Field;
impl Field for Secp256k1Field {
    fn prime() -> BigUint {
        BigUint::parse_bytes(SECP256K1_P_HEX.as_bytes(), 16).unwrap()
    }

    fn a() -> BigUint {
        BigUint::zero()
    }

    fn b() -> BigUint {
        BigUint::from_u8(7).unwrap()
    }
}

/// (Optional) A second curve field, identical parameters to secp256k1’s base field,
/// useful if you want a generic `Point` over any Weierstrass curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericCurveField;
impl Field for GenericCurveField {
    fn prime() -> BigUint {
        BigUint::parse_bytes(SECP256K1_P_HEX.as_bytes(), 16).unwrap()
    }

    fn a() -> BigUint {
        BigUint::zero()
    }

    fn b() -> BigUint {
        BigUint::from_u8(7).unwrap()
    }
}

/// Scalar‐field for secp256k1: Fn where
///     n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1ScalarField;
impl ScalarField for Secp256k1ScalarField {
    fn order() -> BigUint {
        BigUint::parse_bytes(SECP256K1_N_HEX.as_bytes(), 16).unwrap()
    }
}
