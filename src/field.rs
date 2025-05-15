use num_bigint::BigUint;
use num_traits::{FromPrimitive, Zero};

pub trait Field {
    /// The modulus of the field.
    fn prime() -> BigUint;
    /// The “A” in y² = x³ + A·x + B
    fn a() -> BigUint;

    /// The “B” in y² = x³ + A·x + B
    fn b() -> BigUint;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EccPointField;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1GroupField;

impl Field for EccPointField {
    fn prime() -> BigUint {
        let one = BigUint::from_bytes_be(&[0x1]);
        (one.clone() << 256) - &(one << 32) - &BigUint::from_u16(977).unwrap()
    }
    fn a() -> BigUint {
        BigUint::zero()
    }
    fn b() -> BigUint {
        BigUint::from_u64(7).unwrap()
    }
}

impl Field for Secp256k1GroupField {
    fn prime() -> BigUint {
        BigUint::from_bytes_be(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ])
    }
    fn a() -> BigUint {
        BigUint::zero()
    } // y² = x³ + 0·x + 7
    fn b() -> BigUint {
        BigUint::from_u64(7).unwrap()
    }
}
