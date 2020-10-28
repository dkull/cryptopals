#![allow(non_snake_case)]

extern crate cryptopals;

use cryptopals::rsa::RSA;
use std::io::Read;

use num_bigint::{BigUint, ToBigUint};

struct Oracle {
    rsa: RSA,
}
impl Oracle {
    pub fn get_rsa_n(&self) -> BigUint {
        self.rsa.n.clone()
    }

    pub fn pad_encrypt(&self, pt: &BigUint) -> BigUint {
        let padded = self.rsa.pad_pkcs_1_5(&pt.to_bytes_be());
        self.rsa.encrypt(&BigUint::from_bytes_be(&padded))
    }

    pub fn encrypt(&self, pt: &BigUint) -> BigUint {
        self.rsa.encrypt(pt)
    }

    pub fn check(&self, ct: &BigUint) -> bool {
        let mut pt = self.rsa.decrypt(ct).to_bytes_be();
        // add correct missing padding
        let k = self.rsa.n.to_bytes_be().len();
        while pt.len() < k {
            pt.insert(0, 0x00);
        }
        // check if resulting msg is correct
        pt[0] == 0x00 && pt[1] == 0x02
    }
}

fn range_union(existing: &[(BigUint, BigUint)]) -> Vec<(BigUint, BigUint)> {
    if existing.len() <= 1 {
        return existing.to_vec();
    }

    let mut existing = existing.to_vec();
    existing.sort_by(|a, b| (&a.0).partial_cmp(&b.0).unwrap());

    let mut output = vec![];
    let (head, tail) = existing.split_first().unwrap();
    let mut building = head.clone();
    for e in tail {
        if e.0 > &building.1 + 1.to_biguint().unwrap() {
            output.push(building.clone());
            building = e.clone();
        } else {
            let lo = (&building.0).clone();
            let hi = (&building.1).clone().max(e.1.clone());
            building = (lo, hi);
        }
    }

    output.push(building);

    output
}

pub fn main() {
    /*
    authentic verifier we are trying to fool
    */

    let oracle = Oracle { rsa: RSA::new(512) };

    /*
    generate attack
    */

    let pt = b"kick it, CC";
    let ct = oracle.pad_encrypt(&BigUint::from_bytes_be(pt));
    assert!(oracle.check(&ct));

    // helpers
    let bn_1 = &1.to_biguint().unwrap();
    let bn_2 = &2.to_biguint().unwrap();
    let bn_3 = &3.to_biguint().unwrap();
    let bn_8 = &8.to_biguint().unwrap();

    let n = &oracle.get_rsa_n();
    let k = n.to_bytes_be().len() as u32;
    let B = &bn_2.modpow(&(bn_8 * (k - bn_2)), n);

    let two_B = &(B * bn_2);
    let three_B = &(B * bn_3);

    // step 1 - shortcut

    let c0 = &ct;
    let mut s_1 = bn_1.clone();
    let mut M_1 = vec![(two_B.clone(), three_B - bn_1)];

    // steps 2-4
    let mut i = 0_usize;
    loop {
        i += 1;
        println!("iteration: {}", i);

        // step 2(a/b/c) - find si

        let si = if i == 1 || (i > 1 && M_1.len() >= 2) {
            // step 2a/2b
            let mut si = if i == 1 {
                n / three_B
            } else {
                s_1.clone() + bn_1
            };

            loop {
                let res = (c0 * oracle.encrypt(&si)) % n;
                if oracle.check(&res) {
                    break si;
                }
                si += bn_1;
            }
        } else if M_1.len() == 1 {
            // step 2c

            let M_a = &M_1[0].0;
            let M_b = &M_1[0].1;
            let mut ri = bn_2 * (((M_b * &s_1) - two_B) / n);
            'outer: loop {
                let mut si = (two_B + (&ri * n)) / M_b;
                let s_max = (three_B + (&ri * n)) / M_a;
                // <= because we want it to be rounded up
                while si <= s_max {
                    let result = (c0 * oracle.encrypt(&si)) % n;
                    if oracle.check(&result) {
                        break 'outer si.clone();
                    }
                    si += bn_1;
                }
                ri += bn_1;
            }
        } else {
            unreachable!();
        };

        println!("si found: {}", &si);

        // step 3.

        let mut Mi: Vec<(BigUint, BigUint)> = vec![];
        for (M_a, M_b) in M_1.iter() {
            let mut r_min = ((M_a * &si) - three_B + bn_1) / n;
            let r_max = ((M_b * &si) - two_B) / n;
            println!("ma: {} mb: {}", &M_a, &M_b);
            while r_min <= r_max {
                let a_candidate = ((two_B + (&r_min * n)) / &si) + bn_1; // + bn_1 is our ceil
                let b_candidate = (three_B - bn_1 + (&r_min * n)) / &si;

                let a = a_candidate.max((M_a).clone());
                let b = b_candidate.min((M_b).clone());

                if a <= b {
                    Mi.push((a, b));
                }
                r_min += bn_1;
            }
        }

        let Mi = range_union(&Mi);
        println!("found ranges: {}", Mi.len());

        for (a, b) in Mi.iter() {
            println!("range: \na: {}\nb: {}\ndelta: {}", &a, &b, b - a);
        }

        // step 4.

        if Mi.len() == 1 && Mi[0].0 == Mi[0].1 {
            println!("Cracked: {:x?}", Mi[0].0.to_bytes_be());

            let known_pt_padded = oracle.rsa.pad_pkcs_1_5(pt);
            println!("Compare: {:x?}", &known_pt_padded);
            println!("Notice how we have new random padding, but correct msg");
            break;
        }

        M_1 = Mi;
        s_1 = si;
    }
}
