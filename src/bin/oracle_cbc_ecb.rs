extern crate cryptopals;

use std::collections::VecDeque;

fn random_key(length: u8) -> Vec<u8> {
    (0..length)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
}

fn random_encrypt(data: &[u8]) -> (cryptopals::block_ciphers::AESBlockMode, Vec<u8>) {
    // generate the random encryption key
    let key = random_key(16);
    // prepend/append random data
    let mut data: VecDeque<u8> = data.to_vec().into();
    let prepend = (rand::random::<u8>() % 6) + 5;
    let append = (rand::random::<u8>() % 6) + 5;
    for _ in 0..prepend {
        data.push_front(rand::random::<u8>());
    }
    for _ in 0..append {
        data.push_back(rand::random::<u8>());
    }
    let data = Vec::from(data);

    // choose block_mode and encrypt
    let (block_mode, ct, iv) = if rand::random::<f32>() < 0.5 {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&random_key(16));
        let bm = cryptopals::block_ciphers::AESBlockMode::CBC;
        let ct = cryptopals::block_ciphers::aes_encrypt(&data, &key, Some(iv), bm);
        (bm, ct, Some(iv))
    } else {
        let bm = cryptopals::block_ciphers::AESBlockMode::ECB;
        let ct = cryptopals::block_ciphers::aes_encrypt(&data, &key, None, bm);
        (bm, ct, None)
    };
    // test sanity checking
    let pt = cryptopals::block_ciphers::aes_decrypt(&ct, &key, iv, block_mode);
    assert_eq!(pt, data);
    // end sanity check
    (block_mode, ct)
}

fn cbc_ecb_oracle(
    data: &[u8],
) -> (
    cryptopals::block_ciphers::AESBlockMode,
    cryptopals::block_ciphers::AESBlockMode,
) {
    let (known_block_mode, cipher_text) = random_encrypt(&data);
    if cipher_text[16..32] == cipher_text[32..48] {
        (
            known_block_mode,
            cryptopals::block_ciphers::AESBlockMode::ECB,
        )
    } else {
        (
            known_block_mode,
            cryptopals::block_ciphers::AESBlockMode::CBC,
        )
    }
}

fn main() {
    /*
        WIP: Encrypt 3 blocks of null bytes, ECB should have matching blocks
        at some point in the middle, CBC will have random data.
        Oracle checks if block 1 && 2 match == ECB
    */
    eprintln!("(s2c11)");
    let data = [0u8; 16 * 3];
    for _ in 0..50 {
        let (known_block_mode, oracle_guess) = cbc_ecb_oracle(&data);
        assert_eq!(known_block_mode, oracle_guess);
    }
    println!("no assertions hit, so all guessed correct");
}
