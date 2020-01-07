use crate::{hex_to_bytes, xor_arrays};

use aes::Aes128;
use std::collections::VecDeque;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum AESBlockMode {
    ECB,
    CBC,
}

// s2c9
pub fn pkcs7_padding(data: &mut Vec<u8>, block_size: usize) {
    let missing_bytes = block_size - (data.len() % block_size);
    (0..missing_bytes).for_each(|_| data.push(missing_bytes as u8));
}
#[test]
fn pkcs7_padding_works() {
    let mut case1 = (vec![0x00, 0xff, 0x01], vec![0x00, 0xff], 3);
    pkcs7_padding(&mut case1.1, case1.2);
    assert_eq!(case1.0, case1.1);

    let mut case2 = (
        vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01, 0x02, 0x02],
        vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01],
        8,
    );
    pkcs7_padding(&mut case2.1, case2.2);
    assert_eq!(case2.0, case2.1);

    let mut case3 = (vec![0x00, 0xff, 0x02, 0x02], vec![0x00, 0xff], 2);
    pkcs7_padding(&mut case3.1, case3.2);
    assert_eq!(case3.0, case3.1);

    let mut case4 = (vec![0x00, 0xff, 0x01, 0x01], vec![0x00, 0xff, 0x01], 2);
    pkcs7_padding(&mut case4.1, case4.2);
    assert_eq!(case4.0, case4.1);
}

// s2c11
pub fn aes_encrypt(data: &[u8], key: &[u8], iv: Option<[u8; 16]>, mode: AESBlockMode) -> Vec<u8> {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;

    let iv = match iv {
        Some(iv) => iv,
        None => [0u8; 16],
    };

    let mut data = data.to_vec();
    pkcs7_padding(&mut data, 16);

    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let blocks = data.chunks(16).collect::<VecDeque<_>>();

    let mut output = vec![];
    blocks.iter().fold(iv, |prev, block| {
        let block = match mode {
            AESBlockMode::ECB => block.to_vec(),
            AESBlockMode::CBC => xor_arrays(&prev, &block),
        };
        let mut buffer = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut buffer);

        let mut ct = [0u8; 16];
        ct.copy_from_slice(buffer.as_slice());
        output.push(ct.clone());
        ct
    });

    output.concat()
}

#[test]
fn aes_encrypt_works() {
    // NOTE: does not test block mode enough
    // NOTE: we take 0..16 slice because our encrypt adds pkcs7 padding
    let data = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
    let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    let test_vector_cbc = hex_to_bytes("7649abac8119b246cee98e9b12e9197d");
    let test_vector_ecb = hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97");

    let mut iv_real = [0u8; 16];
    iv_real.copy_from_slice(&iv);

    let ct = aes_encrypt(&data, &key, Some(iv_real), AESBlockMode::CBC);
    assert_eq!(ct[0..16].to_vec(), test_vector_cbc);

    let ct = aes_encrypt(&data, &key, Some(iv_real), AESBlockMode::ECB);
    assert_eq!(ct[0..16].to_vec(), test_vector_ecb);
}

// s2c10 (+ s1c7 merged later)
pub fn aes_decrypt(data: &[u8], key: &[u8], iv: Option<[u8; 16]>, mode: AESBlockMode) -> Vec<u8> {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;

    let iv = match iv {
        Some(iv) => iv,
        None => [0u8; 16],
    };

    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let blocks = data.chunks(16).collect::<VecDeque<_>>();

    let mut output = vec![];
    blocks.iter().fold(iv, |prev, block| {
        let mut ct = [0u8; 16];
        ct.copy_from_slice(block);

        let mut buffer = GenericArray::clone_from_slice(&block);
        cipher.decrypt_block(&mut buffer);
        let pt = match mode {
            AESBlockMode::ECB => buffer.as_slice().to_vec(),
            AESBlockMode::CBC => xor_arrays(&prev, buffer.as_slice()),
        };
        output.push(pt);
        ct
    });

    let output = output.concat();
    let padding = output.last().expect("decrypt should produce something");
    output[0..output.len() - (*padding as usize)].to_vec()
}

#[test]
fn aes_decrypt_works() {
    // NOTE: does not test block mode enough
    let data = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
    let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    let test_vector_cbc = hex_to_bytes("7649abac8119b246cee98e9b12e9197d");
    let test_vector_ecb = hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97");

    let mut iv_real = [0u8; 16];
    iv_real.copy_from_slice(&iv);

    let pt = aes_decrypt(&test_vector_cbc, &key, Some(iv_real), AESBlockMode::CBC);
    assert_eq!(pt, data);

    let pt = aes_decrypt(&test_vector_ecb, &key, Some(iv_real), AESBlockMode::ECB);
    assert_eq!(pt, data);
}
