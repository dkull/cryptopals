use crate::{base64_to_bytes, bytes_to_base64, hex_to_bytes, xor_arrays};

use aes::Aes128;
use std::collections::VecDeque;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum AESBlockMode {
    ECB,
    CBC,
    CTR,
}

fn ctr_input(nonce: Option<[u8; 8]>, n: usize) -> [u8; 16] {
    let nonce = if let Some(n) = nonce { n } else { [0u8; 8] };
    let counter = &(n as u64).to_le_bytes();
    let mut adjusted = [0u8; 16];
    adjusted[0..8].copy_from_slice(&nonce);
    adjusted[8..16].copy_from_slice(counter);
    adjusted
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

    let mut case5 = (
        vec![0x00, 0xff, 0x01, 0x01, 0x02, 0x02],
        vec![0x00, 0xff, 0x01, 0x01],
        2,
    );
    pkcs7_padding(&mut case5.1, case5.2);
    assert_eq!(case5.0, case5.1);
}

pub fn pkcs7_padding_strip(data: &mut Vec<u8>) -> bool {
    let padding = data[data.len() - 1];
    // padding can't be more than the whole msg size
    if padding as usize > data.len() {
        return false;
    }
    if padding == 0 {
        return false;
    }
    let padding_start = data.len() - padding as usize;
    for p in padding_start..data.len() {
        if data[p] != padding {
            return false;
        }
    }
    //println!("DEBUG correct padding {}", padding);
    for _ in 0..padding {
        data.pop();
    }
    true
}

#[test]
fn pkcs7_padding_strip_works() {
    let mut data1 = vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01, 0x02, 0x02];
    assert_eq!(pkcs7_padding_strip(&mut data1), true);
    let mut data2 = vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01, 0x02, 0x02, 0x02];
    assert_eq!(pkcs7_padding_strip(&mut data2), true);
    let mut data3 = vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01, 0x02];
    assert_eq!(pkcs7_padding_strip(&mut data3), false);
    let mut data4 = vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01, 0x03];
    assert_eq!(pkcs7_padding_strip(&mut data4), false);
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
    match mode {
        AESBlockMode::ECB | AESBlockMode::CBC => {
            pkcs7_padding(&mut data, 16);
        }
        _ => (),
    }

    let cipher = Aes128::new(GenericArray::from_slice(&key));

    let blocks = data.chunks(16).collect::<VecDeque<_>>();

    let mut output = vec![];
    blocks.iter().enumerate().fold(iv, |prev, (i, block)| {
        let block = match mode {
            AESBlockMode::ECB => block.to_vec(),
            AESBlockMode::CBC => xor_arrays(&prev, &block),
            AESBlockMode::CTR => block.to_vec(),
        };
        // ctr decrypts the counter
        let buffer = match mode {
            AESBlockMode::CTR => {
                let adjusted = ctr_input(None, i);
                let mut buffer = GenericArray::clone_from_slice(&adjusted);
                cipher.encrypt_block(&mut buffer);
                xor_arrays(&buffer.to_vec(), &block).to_vec()
            }
            _ => {
                let mut buffer = GenericArray::clone_from_slice(&block);
                cipher.encrypt_block(&mut buffer);
                buffer.to_vec()
            }
        };

        let mut ct = [0u8; 16];
        ct.copy_from_slice(buffer.as_slice());
        output.push(ct.clone());
        ct
    });

    output.concat()[0..data.len()].to_vec()
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

    // CTR test
    let data_ctr =
        base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let ctr_answer = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();

    let encrypted = aes_encrypt(&ctr_answer, b"YELLOW SUBMARINE", None, AESBlockMode::CTR);
    assert_eq!(encrypted, data_ctr);
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
    blocks.iter().enumerate().fold(iv, |prev, (i, block)| {
        let mut ct = [0u8; 16];
        ct[0..block.len()].copy_from_slice(block);

        // ctr decrypts the counter
        let buffer = match mode {
            AESBlockMode::CTR => {
                let nonce = [0u8; 8];
                let counter = &(i as u64).to_le_bytes();
                let mut adjusted = [0u8; 16];
                adjusted[0..8].copy_from_slice(&nonce);
                adjusted[8..16].copy_from_slice(counter);
                let mut buffer = GenericArray::clone_from_slice(&adjusted);
                cipher.encrypt_block(&mut buffer);
                buffer.to_vec()
            }
            _ => {
                let mut buffer = GenericArray::clone_from_slice(&block);
                cipher.decrypt_block(&mut buffer);
                buffer.to_vec()
            }
        };

        let pt = match mode {
            AESBlockMode::ECB => buffer.as_slice().to_vec(),
            AESBlockMode::CBC => xor_arrays(&prev, buffer.as_slice()),
            AESBlockMode::CTR => xor_arrays(&block, &buffer.as_slice()[0..block.len()]),
        };
        output.push(pt);
        ct
    });

    let mut output = output.concat();
    match mode {
        AESBlockMode::ECB | AESBlockMode::CBC => {
            let good_padding = pkcs7_padding_strip(&mut output);
            // this is ugly, but I do not want to change the interface currently
            if !good_padding {
                return vec![];
            }
            ()
        }
        _ => (),
    }
    output
}

#[test]
fn aes_decrypt_works() {
    // NOTE: does not test block mode enough
    let data = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");
    let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex_to_bytes("000102030405060708090a0b0c0d0e0f");

    let mut iv_real = [0u8; 16];
    iv_real.copy_from_slice(&iv);

    let cbc_ct = aes_encrypt(&data, &key, Some(iv_real), AESBlockMode::CBC);
    let ecb_ct = aes_encrypt(&data, &key, Some(iv_real), AESBlockMode::ECB);

    let pt = aes_decrypt(&cbc_ct, &key, Some(iv_real), AESBlockMode::CBC);
    assert_eq!(pt, data);

    let pt = aes_decrypt(&ecb_ct, &key, Some(iv_real), AESBlockMode::ECB);
    assert_eq!(pt, data);

    // CTR test
    let data_ctr =
        base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let ctr_answer = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();
    let pt = aes_decrypt(&data_ctr, b"YELLOW SUBMARINE", None, AESBlockMode::CTR);
    assert_eq!(pt.to_vec(), ctr_answer);
}
