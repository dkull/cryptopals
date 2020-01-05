use std::io::{self, Read};

pub fn load_stdin() -> String {
    let mut buffer = String::new();
    println!("reading input from stdin...");
    io::stdin().lock().read_to_string(&mut buffer).unwrap();
    buffer
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
        let a = triplet[0];
        let b = triplet[1];
        let c = triplet[2];

        if a == b {
            score -= 1;
        }
        if (a == b) && (b == c) {
            score -= 2;
        }
        if a != b && b != c && b == b' ' {
            score += 2;
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
    assert_eq!(frequency_delta, 74);

    let text = "esto ia";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, 5);

    let text = "estonia hhhhrrrfffmmmlll";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, -28);

    let text = "We have students from different countries and continents gathered here to learn our language with you. At Totally English, you will make international friends and live fantastic learning adventures in the United Kingdom. Together, you will become more proficient in all areas of our language. Being fluent in English has become indispensable in the business area, so take your chance now and improve your skills with Totally English! Be more competitive in your job and see doors open left and right for you. English is the key!We have students from different countries and continents gathered here to learn our language with you. At Totally English, you will make international friends and live fantastic learning adventures in the United Kingdom. Together, you will become more proficient in all areas of our language. Being fluent in English has become indispensable in the business area, so take your chance now and improve your skills with Totally English! Be more competitive in your job and see doors open left and right for you. English is the key!";
    let frequency_delta = english_frequency_score(text.to_string().as_bytes());
    assert_eq!(frequency_delta, 258);
}

pub fn find_xor_key_eng(data: &[u8], _key_len: usize) -> (isize, u8, Vec<u8>) {
    let mut best = (-100, 0x00, vec![]);
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
    let (score, key, output) = find_xor_key_eng(&as_bytes, 1);
    let output = String::from_utf8(output).unwrap();
    assert_eq!(key, 88);
    assert_eq!(output, "Cooking MC's like a pound of bacon");
}
