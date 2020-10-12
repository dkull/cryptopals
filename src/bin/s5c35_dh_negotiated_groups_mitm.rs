extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;
use num_bigint::{BigUint, ToBigUint};

/*

In this attack, in comparison to the previous, we only modify traffic going to Bob
    1) we modify the 'g' sent to Bob - which makes bob generate eg. 0 as pubkey (which causes
        Alices shared key to be also 0)
    2) we modify Alices pubkey sent to Bob to be eg. the same modified g we used in 1)
        This causes Bobs shared key to Also be 0
*/

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
    process(&g, &p, None);

    println!("=== Attacked KEX g<=1");
    process(&g, &p, Some(&1.to_biguint().unwrap()));

    println!("=== Attacked KEX g<=p");
    process(&g, &p, Some(&p));

    println!("=== Attacked KEX g<=p-1");
    process(&g, &p, Some(&(&p - 1.to_biguint().unwrap())));
}

fn process(g: &BigUint, p: &BigUint, attack_g: Option<&BigUint>) {
    /*
    do the DH KEX
    */
    let alice = cryptopals::dh::DiffieHellmanState::new(&g, &p);
    let alice_pubkey = alice.pubkey.clone();
    println!("alice pubkey: {:X}", alice_pubkey);

    // Attack: sending g==[0|1|p|p-1] makes Bobs pubkey either 0 or 1,
    // which makes Alices sharedkey 0 or 1
    let bob = match attack_g {
        None => cryptopals::dh::DiffieHellmanState::new(&g, &p),
        Some(fake_g) => cryptopals::dh::DiffieHellmanState::new(&fake_g, &p),
    };
    let bob_pubkey = bob.pubkey.clone();
    println!("bob pubkey: {:X}", bob_pubkey);

    let alice_sharkey = alice.gen_shared_key(&bob_pubkey);
    let bob_sharkey = match attack_g {
        None => bob.gen_shared_key(&alice_pubkey),
        Some(fake_g) => bob.gen_shared_key(&fake_g),
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
    match attack_g {
        None => println!("Mallory doesn't know how to decrypt the traffic"),
        Some(fake_g) => {
            let shared_key = if fake_g.to_string() == "1" {
                1
            } else if fake_g.to_string() == p.to_string() {
                0
            } else if fake_g.to_string() == (p - 1.to_biguint().unwrap()).to_string() {
                1
            } else {
                panic!();
            };
            let mut mallory_sha1 = cryptopals::sha1::Sha1::new();
            mallory_sha1.update(shared_key.to_string().as_bytes());
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
}
