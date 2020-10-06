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
    cryptopals::block_ciphers::aes_encrypt(&as_bytes, &KEY, None, AESBlockMode::CTR)
}

fn check_admin(data: &[u8]) -> bool {
    let mut as_bytes = cryptopals::block_ciphers::aes_decrypt(&data, &KEY, None, AESBlockMode::CTR);
    cryptopals::block_ciphers::pkcs7_padding_strip(&mut as_bytes);
    let data = String::from_utf8_lossy(&as_bytes);
    println!("admin check on {:?}", data);
    data.contains(";admin=true")
}

fn main() {
    eprintln!("(s4c26)");
    // ascii code for '?'
    let qm = '?' as u8;
    let input = "????????????";
    let target = "x;admin=true";
    let known_offset = 32;

    println!("giving as input: {}", input);

    // this puts our crafted input at exactly index 32, so 2nd block
    let mut ct = create_ciphertext(input);

    // we gave it "???...", and we had it encrypted, we can now xor
    // the pt and ct to get a single byte from the key block.

    for (i, tgt_byte) in target.to_string().as_bytes().iter().enumerate() {
        let shifted_offset = i + known_offset;
        let byte_key = qm ^ ct[shifted_offset];
        let new_val = byte_key ^ tgt_byte;
        ct[shifted_offset] = new_val;
    }

    let result = check_admin(&ct);
    println!("success: {}", result);
}
