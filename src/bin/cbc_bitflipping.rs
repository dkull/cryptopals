extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

const KEY: [u8; 16] = [1u8; 16];
const BS: usize = 16;

fn create_ciphertext(data: &str) -> Vec<u8> {
    let escaped_data = data.replace(";", "").replace("=", "");
    let concatenated = format!(
        "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon",
        escaped_data
    );
    let mut as_bytes = concatenated.bytes().collect::<Vec<_>>();
    cryptopals::block_ciphers::pkcs7_padding(&mut as_bytes, BS);
    cryptopals::block_ciphers::aes_encrypt(&as_bytes, &KEY, None, AESBlockMode::CBC)
}

fn check_admin(data: &[u8]) -> bool {
    let mut as_bytes = cryptopals::block_ciphers::aes_decrypt(&data, &KEY, None, AESBlockMode::CBC);
    cryptopals::block_ciphers::pkcs7_padding_strip(&mut as_bytes);
    let data = String::from_utf8_lossy(&as_bytes);
    println!("admin check on {:?}", data);
    data.contains(";admin=true")
}

fn main() {
    eprintln!("(s2c16)");
    // ascii code for '?'
    let qm = 63;
    let input = "????????????";
    let target = "x;admin=true";
    // i know my data offset, not going to bother forcefully finding it
    let mypos = 32;
    let prevpos = mypos - BS;

    let mut ct = create_ciphertext(input);
    (prevpos..=prevpos + input.len())
        .zip(target.bytes())
        .for_each(|(n, t)| ct[n] ^= qm ^ t);

    let modify_bytes = &ct[prevpos..prevpos + input.len()];
    println!("modifying bytes {:?}", modify_bytes);

    let result = check_admin(&ct);
    println!("success: {}", result);
}
