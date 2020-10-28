extern crate cryptopals;

use cryptopals::rsa::RSA;

use num_bigint::{BigUint, RandBigInt, ToBigUint};

pub fn main() {
    /*
    selftest
    */

    let test_string = "ATTACK AT DAWN";
    let rsa = RSA::new(1024);
    let pt = BigUint::from_bytes_be(test_string.to_string().as_bytes());
    let ct = &rsa.encrypt(&pt);
    let test = rsa.decrypt(ct);
    let test_pt = String::from_utf8(test.to_bytes_be()).unwrap();

    assert_eq!(test_string, test_pt);

    /*
    attack
    */

    // doesn't have to be prime, but it's convenient to call
    let random_nr = &RSA::gen_big_prime(1024) % &rsa.n;

    // a different representation of the CT
    let ct_prime = &(random_nr.modpow(&rsa.e, &rsa.n)) * ct % &rsa.n;
    assert_ne!(ct, &ct_prime);

    let pt_prime = rsa.decrypt(&ct_prime) / random_nr % rsa.n;
    assert_eq!(pt, pt_prime);

    println!("success!");
}
