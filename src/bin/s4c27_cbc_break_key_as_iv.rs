extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

const KEY: [u8; 16] = [7u8; 16];
const BS: usize = 16;

fn create_ciphertext(data: &str) -> Vec<u8> {
    let escaped_data = data.replace(";", "").replace("=", "");
    let concatenated = format!(
        "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon",
        escaped_data
    );
    let mut as_bytes = concatenated.bytes().collect::<Vec<_>>();
    cryptopals::block_ciphers::pkcs7_padding(&mut as_bytes, BS);
    cryptopals::block_ciphers::aes_encrypt(&as_bytes, &KEY, Some(KEY), AESBlockMode::CBC)
}

fn check_admin(data: &[u8]) -> Result<bool, Vec<u8>> {
    let mut as_bytes =
        cryptopals::block_ciphers::aes_decrypt(&data, &KEY, Some(KEY), AESBlockMode::CBC);
    cryptopals::block_ciphers::pkcs7_padding_strip(&mut as_bytes);
    // return raw decrypted bytes on decode error
    match String::from_utf8(as_bytes.clone()) {
        Ok(clean) => Ok(clean.contains(";admin=true")),
        Err(_) => Err(as_bytes),
    }
}

fn main() {
    eprintln!("(s4c27)");
    let ct = create_ciphertext("???????????????");
    println!("! length of ct: {}", ct.len());

    // we know: decrypted block 1 was xored with IV(=key)
    // we know: if we can also get decrypted block 1 without XOR we can get IV
    // so let's make the 3rd block be xored with 2nd CT(0 bytes) to
    // get the third block decrypted with just the key (xor with 0s does nothing).
    // if we then xor 1st and 3rd we get the IV, because that's their only difference
    // NOTE: we are relying on the decrypt logic returning decrypted blocks even if
    // one of the blocks produces invalid ASCII characters.
    let faked_ct = [
        ct[0..16].to_vec(), // first block
        [0u8; 16].to_vec(), // corrupt second block - used for xoring to third
        ct[0..16].to_vec(), // use first block as third - to expose block key (no xor)
        ct[16..].to_vec(),  // use the left of the message so padding works
    ]
    .concat();

    println!("! feeding faked ct");
    let error = check_admin(&faked_ct).expect_err("didn't get an exception. admin?");
    println!("got error, nice! {:?}", error);

    let iv = cryptopals::xor_arrays(&error[0..16], &error[32..48]);
    println!("extracted IV(=key) {:?}", iv);
}
