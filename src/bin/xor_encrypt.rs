extern crate cryptopals;

use std::env;

fn main() {
    eprintln!("(s1c5)");
    let data = cryptopals::load_stdin();
    let key = &env::args().collect::<Vec<_>>()[1];
    eprintln!("using key '{}'", key);

    let data = data.bytes().collect::<Vec<_>>();
    let key = key.bytes().collect::<Vec<_>>();
    let encrypted = cryptopals::xor_arrays(&data, &key);
    let as_hex = cryptopals::bytes_to_hex(&encrypted);
    println!("{}", as_hex);
}
