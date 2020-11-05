extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

const BS: usize = 16;

fn do_cbc_mac(p: &[u8], key: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    let ct = cryptopals::block_ciphers::aes_encrypt(p, key, Some(*iv), AESBlockMode::CBC);
    ct[ct.len() - BS..].to_vec()
}

fn main() {
    eprintln!("(s7c50)");
    let key = b"YELLOW SUBMARINE";
    let pt = b"alert('MZA who was that?');\n";
    let null_block = [0u8; 16];
    let mac = do_cbc_mac(pt, key, &null_block);

    println!("original mac: {}", cryptopals::bytes_to_hex(&mac));

    //
    // attack
    //

    let mut attack = b"alert('Ayo, the Wu is back!');//".to_vec();
    let attack_mac = do_cbc_mac(&attack, key, &null_block);

    /*
        |----------------|----------------|
         alert('Ayo, the  Wu is back!');__  == 296b8d7cb78a243dda4d0a61d33bbdd1
        |----------------|----------------|
    */

    // we got to pad the attack code before using it
    cryptopals::block_ciphers::pkcs7_padding(&mut attack, BS);

    let forged_code = vec![
        attack,
        cryptopals::xor_arrays(&attack_mac, &pt[..BS]),
        pt[BS..].to_vec(),
    ]
    .concat();

    let forgery_mac = do_cbc_mac(&forged_code, key, &null_block);
    println!(
        "forgery mac: {} string: {}",
        cryptopals::bytes_to_hex(&forgery_mac),
        String::from_utf8_lossy(&forged_code)
    );
}
