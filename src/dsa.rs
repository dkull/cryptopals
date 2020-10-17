extern crate openssl;

use crate::sha1::Sha1;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};

pub struct DSA {
    pub p: BigInt,
    pub q: BigInt,
    pub g: BigInt,
    pub pubkey: BigInt,
    pub privkey: BigInt,
}

impl DSA {
    pub fn new() -> DSA {
        let p = BigInt::parse_bytes(
            "800000000000000089e1855218a0e7dac38136ffafa72eda7\
             859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
             2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
             ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
             b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
             1a584471bb1"
                .to_string()
                .as_bytes(),
            16,
        )
        .unwrap();

        let q = BigInt::parse_bytes(
            "f4f47f05794b256174bba6e9b396a7707e563c5b"
                .to_string()
                .as_bytes(),
            16,
        )
        .unwrap();

        let g = BigInt::parse_bytes(
            "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
     458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
     322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
     0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
     878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
     9fc95302291"
                .to_string()
                .as_bytes(),
            16,
        )
        .unwrap();

        let privkey = rand::thread_rng()
            .gen_biguint_below(&q.to_biguint().unwrap())
            .to_bigint()
            .unwrap();
        let pubkey = g.modpow(&privkey, &p);

        DSA {
            p,
            q,
            g,
            pubkey,
            privkey,
        }
    }

    pub fn sign(&self, m: &BigInt) -> (BigInt, BigInt) {
        let p = &self.p;
        let g = &self.g;
        let q = &self.q;

        // ! correct
        // let k = rand::thread_rng().gen_bigint_below(q);
        // ! weak
        let k = rand::thread_rng()
            .gen_biguint_below(&0xffff_u32.to_biguint().unwrap())
            .to_bigint()
            .unwrap();
        let r = self.g.modpow(&k, &p) % q;
        let s = DSA::mod_inv(&k, q).unwrap() * (DSA::hash(m) + (&self.privkey * &r)) % q;

        (r, s)
    }

    pub fn verify(&self, m: &BigInt, r: &BigInt, s: &BigInt) -> bool {
        let p = &self.p;
        let g = &self.g;
        let q = &self.q;

        // if not (0 < r < q) && (0 < s < q) => false
        let w = DSA::mod_inv(s, q).unwrap();
        let u1 = (DSA::hash(m) * &w) % q;
        let u2 = (r * w) % q;
        let v = (g.modpow(&u1, &p) * &self.pubkey.modpow(&u2, &p) % p) % q;
        &v == r
    }

    pub fn hash(m: &BigInt) -> BigInt {
        BigInt::from_signed_bytes_be(&Sha1::digest_now(&m.to_signed_bytes_be()))
    }

    fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if a == &0.to_bigint().unwrap() {
            return (b.clone(), 0.to_bigint().unwrap(), 1.to_bigint().unwrap());
        }
        let (b_div_a, b_mod_a) = (b / a, b % a);
        let (g, x, y) = DSA::egcd(&b_mod_a, a);
        (g, y - (b_div_a * &x), x)
    }

    pub fn mod_inv(a: &BigInt, b: &BigInt) -> Result<BigInt, ()> {
        let a = a.clone().to_bigint().unwrap();
        let b = b.clone().to_bigint().unwrap();
        let (g, x, _) = DSA::egcd(&a, &b);
        if g != 1.to_bigint().unwrap() {
            return Err(());
        }
        if x < 0.to_bigint().unwrap() {
            Ok(((&b + x) % &b).to_bigint().unwrap())
        } else {
            Ok((x % b).to_bigint().unwrap())
        }
    }
}
