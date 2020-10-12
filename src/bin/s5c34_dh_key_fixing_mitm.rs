extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;
use num_bigint::{BigUint, ToBigUint};

pub fn main() {
    let g = 2.to_biguint().unwrap();
    let p = BigUint::parse_bytes(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
    fffffffffffff"
            .to_string()
            .as_bytes(),
        16,
    )
    .unwrap();

    println!("=== Correct KEX");
    process(&g, &p, false);

    println!("=== Attacked KEX");
    process(&g, &p, true);
}

fn process(g: &BigUint, p: &BigUint, attack: bool) {
    /*
    do the DH KEX
    */
    let alice = cryptopals::dh::DiffieHellmanState::new(&g, &p);
    let alice_pubkey = alice.pubkey.clone();

    let bob = cryptopals::dh::DiffieHellmanState::new(&g, &p);
    let bob_pubkey = bob.pubkey.clone();

    let alice_sharkey = if !attack {
        alice.gen_shared_key(&bob_pubkey)
    } else {
        alice.gen_shared_key(&p)
    };
    let bob_sharkey = if !attack {
        bob.gen_shared_key(&alice_pubkey)
    } else {
        bob.gen_shared_key(&p)
    };

    let mut alice_sha1 = cryptopals::sha1::Sha1::new();
    alice_sha1.update(alice_sharkey.to_string().as_bytes());
    let alice_aes_key = &alice_sha1.digest().bytes()[0..16];

    let mut bob_sha1 = cryptopals::sha1::Sha1::new();
    bob_sha1.update(bob_sharkey.to_string().as_bytes());
    let bob_aes_key = &bob_sha1.digest().bytes()[0..16];

    println!(
        "alice shared key: {:X}\n  bob shared key: {:X}",
        alice_sharkey, bob_sharkey
    );
    assert_eq!(alice_sharkey, bob_sharkey);

    /*
    construct Alices message
    */
    let mut alice_iv = [0u8; 16];
    alice_iv.copy_from_slice(&cryptopals::random_key(16));
    let alice_msg = cryptopals::block_ciphers::aes_encrypt(
        b"hello bob!",
        &alice_aes_key,
        Some(alice_iv),
        AESBlockMode::CBC,
    );
    let mut alice_msg = vec![alice_iv.to_vec(), alice_msg].concat();

    /*
    let Bob decrypt the message
    */
    let bob_sees_iv: Vec<u8> = alice_msg.drain(0..16).collect();
    let mut bob_decrypt_iv = [0u8; 16];
    bob_decrypt_iv.copy_from_slice(&bob_sees_iv);
    let bob_decrypts = cryptopals::block_ciphers::aes_decrypt(
        &alice_msg,
        &bob_aes_key,
        Some(bob_decrypt_iv),
        AESBlockMode::CBC,
    );
    println!(
        "Bob received encrypted message: {}",
        String::from_utf8(bob_decrypts.clone()).unwrap()
    );

    /*
    let Bob re-encrypt the message
    */
    let mut bob_iv = [0u8; 16];
    bob_iv.copy_from_slice(&cryptopals::random_key(16));
    let bobs_msg = cryptopals::block_ciphers::aes_encrypt(
        &bob_decrypts,
        &bob_aes_key,
        Some(bob_iv),
        AESBlockMode::CBC,
    );
    let mut bobs_msg = vec![bob_iv.to_vec(), bobs_msg].concat();

    /*
    let Alice read Bobs echoed message
    */
    let alice_sees_iv: Vec<u8> = bobs_msg.drain(0..16).collect();
    let mut alice_decrypt_iv = [0u8; 16];
    alice_decrypt_iv.copy_from_slice(&alice_sees_iv);
    let alice_decrypts = cryptopals::block_ciphers::aes_decrypt(
        &bobs_msg,
        &alice_aes_key,
        Some(alice_decrypt_iv),
        AESBlockMode::CBC,
    );
    println!(
        "Alice received encrypted message: {}",
        String::from_utf8(alice_decrypts).unwrap()
    );

    /*
    let Mallory try to decrypt the traffic
    */
    if !attack {
        println!("Mallory doesn't know how to decrypt the traffic");
    } else {
        let mut mallory_sha1 = cryptopals::sha1::Sha1::new();
        mallory_sha1.update(b"0");
        let mallory_aes_key = &mallory_sha1.digest().bytes()[0..16];
        let mallory_decrypts = cryptopals::block_ciphers::aes_decrypt(
            &bobs_msg, // bobs_msg was intercepted from Bob to Alice
            &mallory_aes_key,
            Some(alice_decrypt_iv), // the IV was prepended to the message, so Mallory saw it
            AESBlockMode::CBC,
        );
        println!(
            "Mallory intercepted encrypted message: {}",
            String::from_utf8(mallory_decrypts).unwrap()
        );
    }
}
