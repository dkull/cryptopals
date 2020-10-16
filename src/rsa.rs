extern crate openssl;

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};

pub struct RSA {
    e: BigUint,
    pub n: BigUint,
    d: BigUint,
    pub pubkey: (BigUint, BigUint),
    privkey: (BigUint, BigUint),
}

impl RSA {
    pub fn new() -> RSA {
        let big_17 = &17.to_biguint().unwrap();
        let big_5 = &5.to_biguint().unwrap();
        //println!(">>> {} {}", big_17 / big_5, big_17 % big_5);
        /*println!(
            ">> {}",
            RSA::mod_inv(&17.to_biguint().unwrap(), &3120.to_biguint().unwrap())
        );*/
        //println!("start!");

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

    pub fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }

    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        c.modpow(&self.d, &self.n)
    }

    fn gen_big_prime() -> BigUint {
        use openssl::bn::BigNum;
        let mut big = BigNum::new().unwrap();

        big.generate_prime(1024, false, None, None).unwrap();
        let prime_bytes = big.to_vec();
        BigUint::from_bytes_be(&prime_bytes)
    }

    fn xgcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
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

    fn _egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if a == &0.to_bigint().unwrap() {
            return (b.clone(), 0.to_bigint().unwrap(), 1.to_bigint().unwrap());
        }
        let (b_div_a, b_mod_a) = (b / a, b % a);
        let (g, x, y) = RSA::_egcd(&b_mod_a, a);
        (g, y - (b_div_a * &x), x)
    }

    // https://rosettacode.org/wiki/Modular_inverse#Rust
    pub fn mod_inv(a: &BigUint, b: &BigUint) -> Result<BigUint, ()> {
        let a = a.clone().to_bigint().unwrap();
        let b = b.clone().to_bigint().unwrap();
        let (g, x, _) = RSA::_egcd(&a, &b);
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
