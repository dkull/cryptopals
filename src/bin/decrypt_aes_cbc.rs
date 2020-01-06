extern crate cryptopals;

use std::env;

fn main() {
    eprintln!("(s2c10)");
    let data = cryptopals::base64_to_bytes(&cryptopals::load_stdin());
    let key = &env::args().collect::<Vec<_>>()[1];
    let key = key.as_bytes();
    let block_mode = cryptopals::block_ciphers::AESBlockMode::CBC;

    let result = cryptopals::block_ciphers::aes_decrypt(&data, &key, None, block_mode);

    let result_readable = String::from_utf8(result).unwrap();
    println!("result: {}", result_readable);
}
