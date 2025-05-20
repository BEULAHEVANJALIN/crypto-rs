// secp256k1.rs — wiring up FieldElement & Scalar types for secp256k1
use crate::{
    field::{Secp256k1Field, Secp256k1ScalarField},
    point::Point,
    scalar::Scalar,
};
use num_bigint::BigUint;
use num_traits::Num;

/// Specialized types
pub type Secp256k1Point = Point<Secp256k1Field>;
pub type Secp256k1Scalar = Scalar<Secp256k1ScalarField>;

/// Generator coordinates (big-endian hex strings)
const G_X: &str = crate::field::SECP256K1_G_X;
const G_Y: &str = crate::field::SECP256K1_G_Y;

impl Secp256k1Point {
    pub fn from_hex_xy(xh: &str, yh: &str) -> Self {
        let x = BigUint::from_str_radix(xh, 16).unwrap();
        let y = BigUint::from_str_radix(yh, 16).unwrap();
        Self::new(x, y, false)
    }

    /// Returns the standard generator G.
    pub fn generator() -> Self {
        Secp256k1Point::from_hex_xy(G_X, G_Y)
    }

    /// Returns the x-coordinate as 32-byte big-endian
    pub fn x_only_bytes(&self) -> [u8; 32] {
        self.x.to_bytes_be()
    }
}

//-----------------------------
// Scalar multiplication impl
//-----------------------------
use std::ops::Mul;

/// Allow &Point * &Scalar → Point
impl<'a> Mul<&'a Secp256k1Scalar> for &'a Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, scalar: &'a Secp256k1Scalar) -> Secp256k1Point {
        // Point::scalar_mul expects &BigUint
        self.scalar_mul(scalar.value())
    }
}

/// Also allow owned Point * &Scalar → Point
impl<'a> Mul<&'a Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, scalar: &'a Secp256k1Scalar) -> Secp256k1Point {
        (&self).mul(scalar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{Num, One};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::str::FromStr;

    /// Check that our generator*scalar matches rust-secp256k1
    fn check_pubkey(hex_priv: &str) {
        let secp = Secp256k1::new();
        let pk_hex = format!("{:0>64}", hex_priv);
        let sk = SecretKey::from_str(&pk_hex).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);

        // our scalar and point
        let priv_big = BigUint::from_str_radix(&pk_hex, 16).unwrap();
        let my_scalar = Secp256k1Scalar::new(priv_big);
        let g = Secp256k1Point::generator();
        let my_point = &g * &my_scalar;

        // compare x,y
        let ser = pk.serialize_uncompressed();
        // skip leading 0x04
        assert_eq!(&ser[1..33], &my_point.x_only_bytes());
        assert_eq!(&ser[33..], &my_point.y.to_bytes_be());
    }

    #[test]
    fn test_small_key() {
        check_pubkey("5");
    }

    use hex;
    use ring::rand::{SecureRandom, SystemRandom};

    pub fn random_32byte_hex() -> String {
        let rng = SystemRandom::new();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).unwrap();
        hex::encode(buf)
    }

    #[test]
    fn test_random_key() {
        let hex_key = random_32byte_hex();
        check_pubkey(&hex_key);
    }

    #[test]
    fn test_scalar_mul() {
        // testing known multiplies of G
        let vectors = vec![
            (
                BigUint::from(7u8),
                "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
                "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da",
            ),
            (
                BigUint::from(1485u16),
                "c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda",
                "7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55",
            ),
            (
                (BigUint::one() << 128),
                "8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
                "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82",
            ),
            (
                ((BigUint::one() << 240) + (BigUint::one() << 31)),
                "9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116",
                "10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053",
            ),
        ];
        let g = Secp256k1Point::generator();
        for (k, xhex, yhex) in vectors {
            let s = Secp256k1Scalar::new(k);
            let p = &g * &s;
            assert_eq!(hex::encode(p.x_only_bytes()), xhex);
            assert_eq!(hex::encode(p.y.to_bytes_be()), yhex);
        }
    }

    /// Compare our point with rust-secp256k1's PublicKey
    fn pub_key_check(pk1: PublicKey, p2: Secp256k1Point) {
        let ser = pk1.serialize_uncompressed();
        // skip 0x04
        assert_eq!(&ser[1..33], &p2.x_only_bytes());
        assert_eq!(&ser[33..65], &p2.y.to_bytes_be());
    }

    #[test]
    fn test_demo() {
        // secret = 5
        let hex_sk = "0000000000000000000000000000000000000000000000000000000000000005";
        let secp = Secp256k1::new();
        let sk = SecretKey::from_str(hex_sk).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &sk);

        // our scalar & point
        let uk = BigUint::from_str_radix(hex_sk, 16).unwrap();
        let s2 = Secp256k1Scalar::new(uk);
        let g = Secp256k1Point::generator();
        let p2 = &g * &s2;
        pub_key_check(pk1, p2);
    }
}
