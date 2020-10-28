extern crate cryptopals;

use cryptopals::rsa::RSA;

use num_bigint::{BigUint, ToBigUint};

struct Oracle {
    rsa: RSA,
}
impl Oracle {
    pub fn get_rsa_n(&self) -> BigUint {
        self.rsa.n.clone()
    }
    pub fn encrypt(&self, pt: &BigUint) -> BigUint {
        self.rsa.encrypt(pt)
    }
    pub fn parity(&self, ct: &BigUint) -> bool {
        let pt = self.rsa.decrypt(ct);
        let tz = pt.trailing_zeros();
        match tz {
            Some(n) => n == 0,
            _ => false,
        }
    }
}

pub fn main() {
    /*
    this attack basically multiplies the plaintext by two until it wraps n.
    this is all the information we need, to know what the plaintext is
    */

    /*
    attack
    */
    let rsa = RSA::new(1024);
    let oracle = Oracle { rsa };
    let secret_pt = BigUint::from_bytes_be(&cryptopals::base64_to_bytes(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==",
    ));

    let pt_two = 2.to_biguint().unwrap();
    let ct_two = &oracle.encrypt(&pt_two);
    let ct = &oracle.encrypt(&secret_pt);

    let n = &oracle.get_rsa_n();
    let mut bounds = (0.to_biguint().unwrap(), n.clone());
    let mut candidate = ct.clone();

    // ~2048 iterations for a 1024 bit key
    let mut i = 0;
    loop {
        candidate *= ct_two;
        let p = oracle.parity(&candidate);
        let mid = (&bounds.0 + &bounds.1) / &pt_two;
        bounds = match p {
            true => (mid.clone(), bounds.1.clone()),
            false => (bounds.0.clone(), mid.clone()),
        };
        println!("bounds [{}]: {}..{}", i, &bounds.0, &bounds.1);
        if &bounds.1 - &bounds.0 == 0.to_biguint().unwrap() {
            break;
        }
        i += 1;
    }
    println!(
        "cracked pt: {}",
        String::from_utf8(bounds.1.to_bytes_be()).unwrap()
    );
}
