extern crate cryptopals;

use std::env;

fn main() {
    eprintln!("(s1c7)");
    let data = cryptopals::base64_to_bytes(&cryptopals::load_stdin());

    let key = &env::args().collect::<Vec<_>>()[1];
    let key = key.as_bytes();

    let result = cryptopals::block_ciphers::decrypt_aes(&data, &key);
    match result {
        Err(reason) => panic!("decrypt failed: {}", reason),
        Ok(r) => {
            let result_readable = String::from_utf8(r).unwrap();
            println!("result: {}", result_readable);
        }
    };
}
