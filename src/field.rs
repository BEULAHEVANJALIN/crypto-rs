use num_bigint::BigUint;
use num_traits::FromPrimitive;

pub trait PrimeField {
    fn prime() -> BigUint;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secp256k1Field;

impl PrimeField for Secp256k1Field {
    fn prime() -> BigUint {
        let one = BigUint::from_bytes_be(&[0x1]);
        (one.clone() << 256) - &(one << 32) - &BigUint::from_u16(977).unwrap() 
    }
}