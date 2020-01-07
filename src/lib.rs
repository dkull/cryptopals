// reexport block_cipher stuff for cryptopals crate users
pub mod block_ciphers;

use std::io::{self, Read};

pub fn load_stdin() -> String {
    let mut buffer = String::new();
    eprintln!("reading input from stdin...");
    io::stdin().lock().read_to_string(&mut buffer).unwrap();
    buffer
}

pub fn random_key(length: u8) -> Vec<u8> {
    (0..length)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<u8>>()
}

pub fn hex_to_bytes(data: &str) -> Vec<u8> {
    let numbers = (b'0'..=b'9').collect::<Vec<u8>>();
    let lowers = (b'a'..=b'f').collect::<Vec<u8>>();
    let lookup = vec![numbers, lowers].concat();
    data.bytes()
        .collect::<Vec<u8>>()
        .chunks(2)
        .map(|d| {
            let val_a = lookup.iter().position(|l| l == &d[0]).expect("first byte");
            let val_b = lookup
                .iter()
                .position(|l| l == &d[1])
                .expect("uneven characters?");
            (val_a * 16 + val_b) as u8
        })
        .collect::<Vec<u8>>()
}

#[test]
fn hex_to_bytes_works() {
    assert_eq!(
        hex_to_bytes("49276d206b00010203".into()),
        [73, 39, 109, 32, 107, 0, 1, 2, 3]
    );
}

fn bits_from_byte(d: u8, a: u32, b: u32) -> u8 {
    assert!(a + b <= 8);
    assert!(b <= 8);
    d.rotate_left(a) >> (8 - b)
}
#[test]
fn bits_from_byte_works() {
    assert_eq!(bits_from_byte(43, 0, 2), 0);
    assert_eq!(bits_from_byte(43, 0, 8), 43);
    assert_eq!(bits_from_byte(43, 4, 4), 11);
    assert_eq!(bits_from_byte(43, 5, 3), 3);
    assert_eq!(bits_from_byte(73, 6, 2), 1);
    assert_eq!(bits_from_byte(73, 6, 2), 1);
}

pub fn bytes_to_base64(data: &[u8]) -> String {
    use std::cmp::min;

    let uppers = (b'A'..=b'Z').collect::<Vec<u8>>();
    let lowers = (b'a'..=b'z').collect::<Vec<u8>>();
    let numbers = (b'0'..=b'9').collect::<Vec<u8>>();
    let extras = vec![b'+', b'/'];
    let lookup = vec![uppers, lowers, numbers, extras].concat();

    let mut current_byte = 0;
    let mut bit_offset = 0;

    let mut output = String::new();
    loop {
        let take_bits = min(6, 8 - bit_offset);
        let mut taken_bits = bits_from_byte(data[current_byte], bit_offset, take_bits);

        // if we are on byte border
        if take_bits < 6 {
            let take_from_next = 6 - take_bits;
            // make room for next bits
            taken_bits <<= take_from_next;
            // take next bits from next byte
            if current_byte + 1 < data.len() {
                taken_bits |= bits_from_byte(data[current_byte + 1], 0, take_from_next);
            }
        }

        bit_offset += 6;
        if bit_offset >= 8 {
            bit_offset %= 8;
            current_byte += 1;
        }

        output.push(lookup[taken_bits as usize] as char);
        if current_byte == data.len() {
            break;
        }
    }
    while output.len() % 4 != 0 {
        output.push('=');
    }
    output
}

#[test]
fn bytes_to_base64_works() {
    let bytes = hex_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".into());
    assert_eq!(
        bytes_to_base64(&bytes),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    assert_eq!(
        bytes_to_base64(&"any carnal pleasure.".bytes().collect::<Vec<_>>()),
        "YW55IGNhcm5hbCBwbGVhc3VyZS4="
    );
}

pub fn base64_to_bytes(data: &str) -> Vec<u8> {
    use std::cmp::min;

    let uppers = (b'A'..=b'Z').collect::<Vec<u8>>();
    let lowers = (b'a'..=b'z').collect::<Vec<u8>>();
    let numbers = (b'0'..=b'9').collect::<Vec<u8>>();
    let extras = vec![b'+', b'/'];
    let lookup = vec![uppers, lowers, numbers, extras].concat();

    let mut output = vec![];

    let mut filled_bits = 0;
    let mut carry = 0;
    for x in data.bytes() {
        let bits = lookup.iter().position(|l| l == &x);
        // skip newlines and such
        let bits = match bits {
            Some(b) => b,
            None => continue,
        } as u8;
        let x = bits;
        let empty_bits = 8 - filled_bits;
        let usable_bits = min(6, 8 - filled_bits);

        // take the bits we can insert
        let mut bits = bits_from_byte(bits, 2, usable_bits);
        // shift them into correct position for ORing
        bits <<= empty_bits - usable_bits;

        carry |= bits;
        filled_bits += usable_bits;
        // if we do not have a full byte assembled yet
        if filled_bits < 8 {
            continue;
        }
        output.push(carry as u8);

        // clear existing data
        carry = 0;
        // fill data for next round
        let from = 2 + usable_bits;
        filled_bits = (8 - from) % 7;
        if filled_bits > 0 {
            carry = bits_from_byte(x, from, 8 - from);
            carry <<= 8 - filled_bits;
        }
    }
    output
}

#[test]
pub fn base64_to_bytes_works() {
    let result = base64_to_bytes("QQABAgNC//8=");
    let reference = [b'A', 0x00, 0x01, 0x02, 0x03, b'B', 0xff, 0xff];
    assert_eq!(result, reference);

    let result = base64_to_bytes("sAAFlG0CAncq3weaDw==");
    let reference = [
        0xb0, 0x00, 0x05, 0x94, 0x6d, 0x02, 0x02, 0x77, 0x2a, 0xdf, 0x07, 0x9a, 0x0f,
    ];
    assert_eq!(result, reference);
}

pub fn bytes_to_hex(data: &[u8]) -> String {
    data.to_vec()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
#[test]
pub fn bytes_to_hex_works() {
    assert_eq!(bytes_to_hex(&[0x00, 0x01, 0x02, 0x03, 0xff]), "00010203ff");
}

pub fn xor_arrays(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert!(a.len() >= b.len());
    a.to_vec()
        .iter()
        .zip(b.to_vec().iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect()
}

#[test]
fn xor_arrays_works() {
    let first = hex_to_bytes("1c0111001f010100061a024b53535009181c");
    let second = hex_to_bytes("686974207468652062756c6c277320657965");
    let result = xor_arrays(&first, &second);
    let in_hex = bytes_to_hex(&result);
    assert_eq!(in_hex, "746865206b696420646f6e277420706c6179");
}

pub fn english_frequency_score(data: &[u8]) -> isize {
    let reference = "etaoins";

    let mut score = 0;
    data.to_vec().windows(3).for_each(|triplet| {
        let a = triplet[0] as char;
        let b = triplet[1] as char;
        let c = triplet[2] as char;

        if a == b {
            score -= 1;
        }
        if (a == b) && (b == c) {
            score -= 2;
        }
        if a != b && b != c && b == ' ' {
            score += 2;
        }

        if (a == '.' || a == ',') && b == ' ' {
            score += 2;
        }

        if !a.is_ascii_alphanumeric() && ![' ', ',', '.'].contains(&a) {
            score -= 1;
        }

        if reference.contains(|r| r == (a as char)) {
            score += 1;
        } else {
            score -= 1;
        }
    });
    score
}

#[test]
fn english_frequency_score_works() {
    let text = "snniiiooooaaaaatttttteeeeeee ";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, -24);

    let text = "Man is distinguished, not only by his reason, but by this singular passion from other animals,
which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable 
generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, 80);

    let text = "esto ia";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, 5);

    let text = "estonia hhhhrrrfffmmmlll";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, -28);

    let text = "We have students from different countries and continents gathered here to learn our language with you. At Totally English, you will make international friends and live fantastic learning adventures in the United Kingdom. Together, you will become more proficient in all areas of our language. Being fluent in English has become indispensable in the business area, so take your chance now and improve your skills with Totally English! Be more competitive in your job and see doors open left and right for you. English is the key!We have students from different countries and continents gathered here to learn our language with you. At Totally English, you will make international friends and live fantastic learning adventures in the United Kingdom. Together, you will become more proficient in all areas of our language. Being fluent in English has become indispensable in the business area, so take your chance now and improve your skills with Totally English! Be more competitive in your job and see doors open left and right for you. English is the key!";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, 283);
}

pub fn find_xor_key_eng(data: &[u8]) -> (isize, u8, Vec<u8>) {
    let mut best = (-0xffff, 0x00, vec![]);
    for b in 1..=255u8 {
        let decrypted = xor_arrays(data, &[b]);
        let score = english_frequency_score(&decrypted);
        if score > best.0 {
            best = (score, b, decrypted);
        }
    }
    best
}
#[test]
fn find_xor_key_eng_works() {
    let text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let as_bytes = hex_to_bytes(text);
    let (_score, key, output) = find_xor_key_eng(&as_bytes);
    let output = String::from_utf8(output).unwrap();
    assert_eq!(key, 88);
    assert_eq!(output, "Cooking MC's like a pound of bacon");
}

pub fn search_xor_key(data: &[u8], key_len: usize) -> (isize, Vec<u8>, Vec<u8>) {
    use std::cmp::max;
    let mut best_guesses = vec![];
    let mut best_key = vec![];
    let mut longest = 0;
    let mut sum_of_scores = 0;

    for offset in 0..key_len {
        let nth_bytes = data
            .iter()
            .enumerate()
            .filter(|(i, _)| i % key_len == offset)
            .map(|(_, b)| *b)
            .collect::<Vec<_>>();

        let best_guess = find_xor_key_eng(&nth_bytes);
        longest = max(best_guess.2.len(), longest);
        best_guesses.push(best_guess.2.clone());
        best_key.push(best_guess.1);
        sum_of_scores += best_guess.0;
    }

    let mut result = vec![];
    for i in 0..longest {
        for c in best_guesses.iter() {
            if i >= c.len() {
                continue;
            }
            result.push(c[i]);
        }
    }

    (sum_of_scores, best_key, result)
}

#[test]
fn search_xor_key_works() {
    let data = "LAgaCA9BAQQMCU0EDxEZGBwZBAVSDwAYDEFJUAgIHAUEEwYOGRhPSE1SHwkJTQYOEwdBAwtBFRoOQQ8fGBEGCg8NARgSBksIH00VDlIMAAUDQQABSwwZDglBGwUHAx8MAAYCDgJNABJSGw4fHggDHg5BDQ8OFAZLFQQIQQ4AAgYFAwANXksUAggPAgASERgIBUEWChUNTUlDAgcABQMVBAofQ0VDQSgGSwgfTRQSFw0UAE0VDlIIDgIeCAUXGUEYGg5BExgRCQ4VElIEB0wMAgkbDhcFAwZBBgMIH0NBNRoOQQoEExIGSwgfTQMTFwoKBQMGQQYDBEweGBIGDgxMj+H1Uh8JDRlBCAFLBQUeAg4EDhMFAwZBGgQWTBkJBFIODw8EEQkXGQwJAxVBAhkODwgSElIcDh4GEk9SPwkJTRIEEQQPCE0IElIYDgAbCA8VSxUECEEKFxJBGAUAFVICEkwYDwgDHgRMCw4TUgpBHAwTFRsIFAAME0EXBQIeFBEVFw9BAQgSEhMMBEwCE0EVGQ4ZHUEOFEsMCR4SABUOEkJn";
    let data = base64_to_bytes(&data);
    let best_result = search_xor_key(&data, 7);

    let result_readable = String::from_utf8(best_result.2.clone()).unwrap();

    assert_eq!(best_result.1, [b'k', b'a', b'l', b'm', b'a', b'a', b'r']);
    assert!(result_readable.starts_with("Given some encrypted data (\"ciphertext"));
}
