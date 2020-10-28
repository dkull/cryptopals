extern crate cryptopals;

use cryptopals::rsa::RSA;
use std::io::Read;

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use sha2::{Digest, Sha256};

pub fn main() {
    /*
    authentic verifier we are trying to fool
    */

    let authentic_verifier = RSA::new(1024);

    /*
    generate attack
    we do not use correct PKCS1_v1.5 padding/signatures. but an analogous dummy
    i may have missed something here, but seems to work
    */

    let forged_msg_bytes: &[u8] = b"hi mom";
    let forged_msg = BigUint::from_bytes_be(forged_msg_bytes);
    let forged_digest: Vec<u8> = Sha256::digest(&forged_msg_bytes).to_vec();

    // my bignum conversion deletes the first 0x00 byte, so we leave it off
    let forged_padded_msg = &mut vec![[0x01, 0xff, 0x00].to_vec(), forged_digest].concat();
    /*let forged_padded_msg = &mut authentic_verifier
    .pad_pkcs_1_5(&BigUint::from_bytes_be(&forged_digest))
    .to_bytes_be();*/

    for _ in 0..200 {
        // add a bunch of 0x01 bytes that the cbrt will overwrite
        // but the verifier won't read them at all
        forged_padded_msg.push(0x01);
    }
    let forged_padded_msg = BigUint::from_bytes_be(forged_padded_msg);
    let forged_signature = &forged_padded_msg.cbrt();

    println!(
        "verified forged signature: {}",
        authentic_verifier.verify(&forged_msg, &forged_signature)
    );
}
