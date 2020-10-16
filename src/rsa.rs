extern crate openssl;

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};
use sha2::{Digest, Sha256};

pub struct RSA {
    pub e: BigUint,
    pub n: BigUint,
    d: BigUint,
    pub pubkey: (BigUint, BigUint),
    privkey: (BigUint, BigUint),
}

impl RSA {
    pub fn new() -> RSA {
        let big_1 = &1.to_biguint().unwrap();

        let e = &3.to_biguint().unwrap();
        loop {
            let p = &RSA::gen_big_prime();
            let q = &RSA::gen_big_prime();
            let n = &(p * q);
            let et = ((p - big_1) * (q - big_1)) % n;
            match RSA::mod_inv(&e, &et) {
                Err(_) => continue,
                Ok(d) => {
                    return RSA {
                        e: e.to_owned(),
                        n: n.to_owned(),
                        d: d.to_owned(),
                        pubkey: (e.clone(), n.clone()),
                        privkey: (d.clone(), n.clone()),
                    }
                }
            };
        }
        unreachable!();
    }

    /*
    this function is 100% fake and does just enough to do the task
    */
    pub fn verify(&self, m: &BigUint, sig: &BigUint) -> bool {
        let padded_sig = self.encrypt(sig).to_bytes_be();
        let mut state = 0;
        for (i, cur_byte) in padded_sig.iter().enumerate() {
            let next_byte = padded_sig[i + 1];
            if state == 0 {
                assert_eq!(&0x01_u8, cur_byte);
                state = 1;
                continue;
            }
            if state == 1 && cur_byte == &0xff_u8 && next_byte == 0x00_u8 {
                // take the 64 bytes of digest
                let provided_digest: &[u8] = &padded_sig[i + 2..i + 2 + 32];
                let calced_digest: &[u8] = &Sha256::digest(&m.to_bytes_be());
                return provided_digest == calced_digest;
            }
        }
        false
    }

    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }

    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        c.modpow(&self.d, &self.n)
    }

    pub fn gen_big_prime() -> BigUint {
        use openssl::bn::BigNum;
        let mut big = BigNum::new().unwrap();

        big.generate_prime(1024, false, None, None).unwrap();
        let prime_bytes = big.to_vec();
        BigUint::from_bytes_be(&prime_bytes)
    }

    /*
    unusded
    alternative to egcd
    */
    fn _xgcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        let (mut x0, mut x1, mut y0, mut y1) = (
            0.to_bigint().unwrap(),
            1.to_bigint().unwrap(),
            1.to_bigint().unwrap(),
            0.to_bigint().unwrap(),
        );

        let mut a = a.clone();
        let mut b = b.clone();

        while a != 0.to_bigint().unwrap() {
            let (q, _a) = (&b / &a, &b % &a);
            b = a;
            a = _a;
            let (_y0, _y1) = (&y1, &y0 - (&q * &y1));
            y0 = _y0.clone();
            y1 = _y1;
            let (_x0, _x1) = (&x1, &x0 - (&q * &x1));
            x0 = _x0.clone();
            x1 = _x1;
        }
        (b, x0, y0)
    }

    fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if a == &0.to_bigint().unwrap() {
            return (b.clone(), 0.to_bigint().unwrap(), 1.to_bigint().unwrap());
        }
        let (b_div_a, b_mod_a) = (b / a, b % a);
        let (g, x, y) = RSA::egcd(&b_mod_a, a);
        (g, y - (b_div_a * &x), x)
    }

    // https://rosettacode.org/wiki/Modular_inverse#Rust
    pub fn mod_inv(a: &BigUint, b: &BigUint) -> Result<BigUint, ()> {
        let a = a.clone().to_bigint().unwrap();
        let b = b.clone().to_bigint().unwrap();
        let (g, x, _) = RSA::egcd(&a, &b);
        //println!(">> g:{} x:{}", g, x);
        if g != 1.to_bigint().unwrap() {
            return Err(());
        }
        if x < 0.to_bigint().unwrap() {
            Ok(((&b + x) % &b).to_biguint().unwrap())
        } else {
            Ok((x % b).to_biguint().unwrap())
        }
    }
}

#[test]
fn test_rsa() {
    let rsa = RSA::new();
    let val = 42.to_biguint().unwrap();
    assert_eq!(rsa.decrypt(rsa.encrypt(val)), val);
}
