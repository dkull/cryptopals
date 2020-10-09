extern crate byteorder;
extern crate cryptopals;

use std::fmt::Write;
use std::process::exit;

use byteorder::{BigEndian, LittleEndian, WriteBytesExt};

fn md4_padding(data_len: usize) -> Vec<u8> {
    let mut padding: Vec<u8> = vec![0x80];
    while ((data_len + padding.len()) % 64) != 56 {
        padding.push(0x00);
    }
    padding
        .write_u32::<LittleEndian>((data_len * 8) as u32)
        .unwrap();
    padding.write_u32::<BigEndian>(0).unwrap();
    padding
}

fn digest_to_str(digest: &[u32]) -> String {
    let mut s = String::new();
    for &word in digest {
        write!(&mut s, "{:08x}", word).unwrap();
    }
    s
}

struct Authenticator {
    key: Vec<u8>,
}
impl Authenticator {
    fn new(key: &[u8]) -> Authenticator {
        Authenticator { key: key.to_vec() }
    }
    fn verify(&self, msg: &[u8], mac: &[u32]) -> bool {
        let mut good_input = vec![];
        good_input.extend(&self.key);
        good_input.extend(msg);
        let real_mac = cryptopals::md4::md4(good_input, 0, None);
        real_mac == mac
    }
}

pub fn main() {
    let key = "foobar".to_string();
    let msg =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_string();
    let attack = ";admin=true";

    let authenticator = Authenticator::new(key.as_bytes());

    // create hasher
    let mut good_input = vec![];
    good_input.extend(key.as_bytes());
    good_input.extend(msg.as_bytes());
    let original_mac = cryptopals::md4::md4(good_input.clone(), 0, None);

    /*good_input.extend(md4_padding(key.len() + msg.len()));
    good_input.extend(attack.to_string().as_bytes());
    let expected_mac = cryptopals::md4::md4(good_input, 0, None);
    println!(
        "expecting result digest; {} / {:?}",
        digest_to_str(&expected_mac),
        expected_mac
    );*/

    //
    // start bruteforcing a modified MAC
    //

    // lift the internal state
    for key_len in 1..64 {
        // just bruteforce the data len - could be calculated
        for data_len in 1..256 {
            let faked_mac = cryptopals::md4::md4(
                attack.as_bytes(),
                data_len,
                Some(&[
                    u32::from_be(original_mac[0]),
                    u32::from_be(original_mac[1]),
                    u32::from_be(original_mac[2]),
                    u32::from_be(original_mac[3]),
                ]),
            );

            let faked_padding = md4_padding(key_len + msg.len());
            let mut faked_msg = msg.as_bytes().to_vec();
            faked_msg.extend(&faked_padding);
            faked_msg.extend(attack.as_bytes());
            let matches = authenticator.verify(&faked_msg, &faked_mac);
            if matches {
                println!(
                    "!!! found keylen {} datalen {} {} {:?}",
                    key_len,
                    data_len,
                    String::from_utf8_lossy(&faked_msg),
                    digest_to_str(&faked_mac),
                );
                exit(0);
            }
        }
    }
}
