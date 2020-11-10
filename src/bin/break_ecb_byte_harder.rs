extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

fn provably_ecb(block_size: usize) -> bool {
    let key = vec![0u8; block_size];
    let data = vec![0u8; block_size * 3];
    let ct = cryptopals::block_ciphers::aes_encrypt(&data, &key, None, AESBlockMode::ECB);
    ct[16..32] == ct[32..48]
}

fn cbc_ecb_oracle(key: &[u8], prepend: &[u8], data: &[u8], append: &[u8]) -> Vec<u8> {
    cryptopals::block_ciphers::aes_encrypt(
        &vec![prepend, data, append].concat(),
        &key,
        None,
        AESBlockMode::ECB,
    )
}

fn main() {
    eprintln!("(s2c14)");
    let append = cryptopals::base64_to_bytes(&cryptopals::load_stdin());
    let static_key = cryptopals::random_key(16 as usize);

    // detecting a block size does not make sense
    let block_size = 16;
    let is_ecb = provably_ecb(block_size);
    assert!(is_ecb);

    // create a collection of random bytes  for prefixing
    let prepend = (1..rand::random::<u8>())
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();

    // determine the random prefix length
    let mut last_oracle_len = 0;
    let mut extracted_random_bytes_count = 0;
    for i in 0u8..=255u8 {
        // i'm sending a byte on the principle that I have to send something
        let oracle_ct_len =
            cbc_ecb_oracle(&static_key, &prepend, &vec![0; i as usize], &append).len();
        if i != 0 && oracle_ct_len > last_oracle_len {
            // remove a block, because it is full of padding
            let data_filled_blocks = (oracle_ct_len / block_size) - 1;
            extracted_random_bytes_count =
                (data_filled_blocks * block_size) - append.len() - i as usize;
            break;
        }
        last_oracle_len = oracle_ct_len;
    }
    println!(
        "found experimentally that random bytes == {}",
        extracted_random_bytes_count
    );

    // use the found random byte count to move our extracting pos and allocate less attack bytes
    let mut extracting_pos = ((append.len() + block_size) / block_size) * block_size - 1;
    extracting_pos += ((extracted_random_bytes_count + block_size) / block_size) * block_size;
    let mut attack_data = vec![0; extracting_pos - extracted_random_bytes_count];
    let mut extracted_data = vec![];

    // the same as in s2c12
    for i in 0..append.len() {
        let oracle_ct = cbc_ecb_oracle(&static_key, &prepend, &attack_data, &append);
        for candidate in 0u8..=255u8 {
            let test_ct = cbc_ecb_oracle(
                &static_key,
                &prepend,
                &vec![
                    attack_data.clone(),
                    extracted_data.clone(),
                    [candidate].to_vec(),
                ]
                .concat(),
                &append,
            );
            if test_ct[0..=extracting_pos] == oracle_ct[0..=extracting_pos] {
                println!("found {}. => {:x}", i, candidate);
                extracted_data.push(candidate);
                attack_data.pop();
                break;
            }
        }
    }
    let output = String::from_utf8(extracted_data).unwrap();
    println!("{}", output);
}
