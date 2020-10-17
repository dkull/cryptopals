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

    println!(
        "orig sig verified {} : r: {:x} s: {:x}",
        verified, sig.0, sig.1
    );

    /*
    g=0 attack
    */

    let fake_dsa = DSA::new_with_g(0.to_bigint().unwrap());
    let fake_sig = fake_dsa.sign(&msg_bn);
    let fake_verified = fake_dsa.verify(&msg_bn, &fake_sig.0, &fake_sig.1);
    println!(
        "fake (g=0) sig verified {} : r: {:x} s: {:x}",
        fake_verified, fake_sig.0, fake_sig.1
    );

    /*
    g=(p+1) attack
    */

    let fake_dsa = DSA::new_with_g(&(dsa.p) + 1.to_bigint().unwrap());
    let fake_sig = fake_dsa.sign(&msg_bn);
    let fake_verified = fake_dsa.verify(&msg_bn, &fake_sig.0, &fake_sig.1);
    println!(
        "fake (g=p+1) sig verified {} : r: {:x} s: {:x}",
        fake_verified, fake_sig.0, fake_sig.1
    );

    let z = BigInt::from_signed_bytes_be(b"LANK");
    let universal_r = &fake_dsa.pubkey.modpow(&z, &fake_dsa.p) % &fake_dsa.q;
    let universal_s = &universal_r * DSA::mod_inv(&z, &fake_dsa.q).unwrap() % &fake_dsa.q;

    // verify universal sig with random msg

    assert!(fake_dsa.verify(
        &BigInt::from_signed_bytes_be(b"AB"),
        &universal_r,
        &universal_s,
    ));
    assert!(fake_dsa.verify(
        &BigInt::from_signed_bytes_be(b"CD"),
        &universal_r,
        &universal_s,
    ));
}
