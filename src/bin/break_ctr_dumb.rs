extern crate cryptopals;

use std::collections::VecDeque;

use cryptopals::block_ciphers::AESBlockMode;

fn random_key(length: u8) -> Vec<u8> {
    (0..length)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
}

fn ascii_guess(nth_byte: usize, data: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut good_bytes = vec![];
    for key_guess in 0..255 {
        let is_good = data
            .iter()
            .map(|line| {
                if line.len() <= nth_byte {
                    true
                } else {
                    let pt_guess = line[nth_byte] ^ key_guess;
                    pt_guess >= 32 && pt_guess <= 126
                    //pt_guess >= 97 && pt_guess <= 122
                }
            })
            .all(|x| x);
        if is_good {
            good_bytes.push(key_guess);
        }
    }
    good_bytes
}

fn main() {
    println!("(s3c19)");
    println!("######################################################################");
    println!("THIS DOES NOT DETERMINE THE EXACT CORRECT KEYSTREAM, BUT IT GETS CLOSE");
    println!("######################################################################");
    println!();

    let data = cryptopals::load_stdin();
    let lines = data.lines();
    let key = random_key(16);

    // encrypt all the input lines
    let cts = lines
        .map(|line| {
            cryptopals::block_ciphers::aes_encrypt(
                // decode the base64 to raw bytes
                &cryptopals::base64_to_bytes(line),
                &key[..],
                None,
                AESBlockMode::CTR,
            )
        })
        .collect::<Vec<_>>();

    println!("all input lines ({}) encrypted", cts.len(),);

    let mut guessed_key: Vec<u8> = vec![];
    for x in 0..255 {
        let guesses = ascii_guess(x, &cts);
        for g in &guesses {
            let col_guess_bytes = &cts
                .iter()
                .filter_map(|ct| {
                    if ct.len() > x {
                        Some((ct[x] ^ g) as u8)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            let col_guess_score = cryptopals::english_frequency_score(col_guess_bytes);
            if col_guess_score >= 0 {
                guessed_key.push(*g);
                break;
            }
        }
    }

    for ct in &cts {
        let mut decrypted = vec![];
        for (key_byte, ct_byte) in ct.to_vec().iter().zip(guessed_key.to_vec()) {
            decrypted.push(key_byte ^ ct_byte);
        }
        println!("> {}", String::from_utf8_lossy(&decrypted));
    }
}
