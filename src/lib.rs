use std::io::{self, Read};

pub fn load_stdin() -> String {
    let mut buffer = String::new();
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
                .expect(format!("second byte {:?} not in {:?}", d, lookup).as_str());
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
