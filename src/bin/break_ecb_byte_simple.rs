extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

fn provably_ecb(block_size: usize) -> bool {
    let key = vec![0u8; block_size];
    let data = vec![0u8; block_size * 3];
    println!(">> {} {}", key.len(), data.len());
    let ct = cryptopals::block_ciphers::aes_encrypt(&data, &key, None, AESBlockMode::ECB);
    ct[16..32] == ct[32..48]
}

fn cbc_ecb_oracle(key: &[u8], data: &[u8], append: &[u8]) -> Vec<u8> {
    cryptopals::block_ciphers::aes_encrypt(
        &vec![data, append].concat(),
        &key,
        None,
        AESBlockMode::ECB,
    )
}

fn main() {
    eprintln!("(s2c12)");
    let append = cryptopals::base64_to_bytes(&cryptopals::load_stdin());
    let static_key = cryptopals::random_key(16);

    // detecting a block size does not make sense
    let block_size = 16;
    let is_ecb = provably_ecb(block_size);
    assert!(is_ecb);

    let extracting_pos = (((append.len() / block_size) + 1) * block_size) - 1;

    let mut prepend_data = vec![0; extracting_pos];
    let mut extracted_data = vec![];

    for i in 0..append.len() {
        let oracle_ct = cbc_ecb_oracle(&static_key, &prepend_data, &append);
        for candidate in 0u8..=255u8 {
            let test_ct = cbc_ecb_oracle(
                &static_key,
                &vec![
                    prepend_data.clone(),
                    extracted_data.clone(),
                    [candidate].to_vec(),
                ]
                .concat(),
                &append,
            );
            if test_ct[0..=extracting_pos] == oracle_ct[0..=extracting_pos] {
                println!("found {}. => {:x}", i, candidate);
                extracted_data.push(candidate);
                prepend_data.pop();
            }
        }
    }
    let output = String::from_utf8(extracted_data).unwrap();
    println!("{}", output);
}
