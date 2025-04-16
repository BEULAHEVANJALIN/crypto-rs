use crate::{field::EccPointField, point::Point, scalar::Scalar};
use num_bigint::BigUint;

pub type Secp256k1Point = Point<EccPointField>;

impl Secp256k1Point {
    pub fn generator() -> Secp256k1Point {
        let gx = BigUint::from_bytes_be(&[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ]);
        let gy = BigUint::from_bytes_be(&[
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
            0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
            0xFB, 0x10, 0xD4, 0xB8,
        ]);

        Secp256k1Point {
            x: Scalar::new(gx),
            y: Scalar::new(gy),
            infinite: false,
        }
    }

    pub fn x_only_bytes(&self) -> Vec<u8> {
        self.x.value.to_bytes_be()
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Instant};

    use crate::{
        field::{Field, Secp256k1GroupField},
        scalar::Scalar,
    };

    use super::*;
    use num_traits::{FromPrimitive, Num};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn pub_key_check(p1: PublicKey, p: Secp256k1Point) {
        let pk = hex::encode(&p1.serialize_uncompressed()[1..]);
        assert_eq!(pk.len(), 128);
        assert_eq!(&pk[0..64], &(p.x.to_hex()[2..]));
        assert_eq!(&pk[64..], &(p.y.to_hex()[2..]));
    }

    #[test]
    fn test_demo() {
        let g = Secp256k1Point::generator();
        let secp = &Secp256k1::new();
        let k = "0000000000000000000000000000000000000000000000000000000000000005";
        let sk = SecretKey::from_str(k).unwrap();
        let p1 = PublicKey::from_secret_key(secp, &sk);

        let uk = BigUint::from_str_radix(k, 16).unwrap();
        let p = Scalar::<Secp256k1GroupField>::new(uk) * &g;

        pub_key_check(p1, p);
    }

    #[test]
    fn test_scalar_mul() {
        let one = BigUint::from_bytes_be(&[0x1]);
        let points = vec![
            (
                BigUint::from_u8(7).unwrap(),
                "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
                "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da",
            ),
            (
                BigUint::from_u64(1485).unwrap(),
                "c982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda",
                "7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55",
            ),
            (
                one.clone() << 128,
                "8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
                "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82",
            ),
            (
                (one.clone() << 240) + &(one << 31),
                "9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116",
                "10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053",
            ),
        ];

        let sec_point_vec: Vec<_> = points
            .iter()
            .map(|(sec, x, y)| (sec, Secp256k1Point::from_hex_xy(x, y)))
            .collect();
        assert_eq!(sec_point_vec.len(), points.len());
        let g = Secp256k1Point::generator();

        for (i, (k, x, y)) in points.iter().enumerate() {
            let start = Instant::now();
            let p = Scalar::<Secp256k1GroupField>::new(k.clone()) * &g;
            let duration = start.elapsed();
            println!("Time elapsed in my_function() is: {:?}", duration);
            assert_eq!(&(p.x.to_hex()[2..]), *x, "at {i}");
            assert_eq!(&(p.y.to_hex()[2..]), *y, "at {i}");
        }
    }

    #[test]
    fn test_order() {
        let res = (Scalar::<Secp256k1GroupField>::new(Secp256k1GroupField::prime())
            * &Secp256k1Point::generator())
            .is_infinite();
        assert!(res);
    }
}
