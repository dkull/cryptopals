extern crate cryptopals;

use cryptopals::rsa::RSA;

use num_bigint::{BigUint, RandBigInt, ToBigUint};

pub fn main() {
    /*
    selftest
    */

    let test_string = "ATTACK AT DAWN";
    let rsa = RSA::new();
    let pt = BigUint::from_bytes_be(test_string.to_string().as_bytes());
    let test = rsa.decrypt(&rsa.encrypt(&pt));
    let test_pt = String::from_utf8(test.to_bytes_be()).unwrap();

    assert_eq!(test_string, test_pt);

    /*
    generate attack data
    */

    let rsas = vec![RSA::new(), RSA::new(), RSA::new()];

    let cts = rsas.iter().map(|rsa| rsa.encrypt(&pt)).collect::<Vec<_>>();

    let sum: BigUint = vec![(0, 1, 2), (1, 0, 2), (2, 0, 1)]
        .into_iter()
        .map(|(nth, a_n, b_n)| {
            let m = &(&rsas[a_n].n * &rsas[b_n].n);
            &cts[nth] * m * RSA::mod_inv(m, &rsas[nth].n).unwrap()
        })
        .sum();

    let n123: BigUint = rsas.iter().map(|x| &x.n).product();

    let result = (sum % n123).cbrt();

    assert_eq!(result, pt);
    println!("success!");
}
