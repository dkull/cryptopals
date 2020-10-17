extern crate cryptopals;

use cryptopals::dsa::DSA;
use cryptopals::sha1::Sha1;
use std::io::Read;

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};

pub fn main() {
    /*
    authentic verifier we are trying to fool
    */

    let msg = b"ATTACK AT DAWN";
    let msg_bn = BigInt::from_signed_bytes_be(msg);

    let dsa = DSA::new();
    let sig = dsa.sign(&msg_bn);
    let verified = dsa.verify(&msg_bn, &sig.0, &sig.1);

    println!("selftest: {}", verified);

    /*
    attack
    */

    let msg_hash = BigInt::from_signed_bytes_be(&Sha1::digest_now(msg));
    let r = sig.0;
    let s = sig.1;
    for k_candidate in 1..0xffff_u32 {
        let k_candidate = k_candidate.to_bigint().unwrap();
        let x = ((&s * &k_candidate) - &msg_hash) * DSA::mod_inv(&r, &dsa.q).unwrap() % &dsa.q;
        println!("k: {}", k_candidate);
        if dsa.pubkey == dsa.g.modpow(&x, &dsa.p) {
            println!("found k [{}] ! x => {:x}", &k_candidate, &x);
            break;
        }
    }
}
