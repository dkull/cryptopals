extern crate byteorder;
extern crate cryptopals;

use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use std::convert::TryInto;

fn sha1_padding(data_len: usize) -> Vec<u8> {
    let mut padding: Vec<u8> = vec![0x80];
    while ((data_len % 64 + padding.len()) % 60) != 0 {
        padding.push(0x00);
    }
    padding
        .write_u32::<BigEndian>((data_len * 8) as u32)
        .unwrap();
    padding
}

struct Authenticator {
    key: Vec<u8>,
}
impl Authenticator {
    fn new(key: &[u8]) -> Authenticator {
        Authenticator { key: key.to_vec() }
    }
    fn verify(&self, msg: &[u8], mac: &[u8]) -> bool {
        let mut m = cryptopals::sha1::Sha1::new();
        m.update(&self.key);
        m.update(msg);
        m.digest().bytes() == mac
    }
}

pub fn main() {
    let key = "foobar".to_string();
    let msg =
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_string();
    let attack = ";admin=true";

    let authenticator = Authenticator::new(key.as_bytes());

    // create hasher
    let mut m = cryptopals::sha1::Sha1::new();
    m.update(key.as_bytes());
    m.update(msg.as_bytes());

    // extract hash of key+msg+implicit_padding
    let authentic_digest_bytes = m.digest().bytes();

    /* // calculate the expected correct modified result mac
    let assumed_padding = sha1_padding(key.len() + msg.len());
    m.update(&assumed_padding);
    m.update(&attack.as_bytes());
    let expected_digest = m.digest();
    println!(
        "=== digest of expected fake : {} ===",
        expected_digest.to_string(),
    );*/

    //
    // start bruteforcing a modified MAC
    //

    // lift the internal state
    let faked_state = [
        u32::from_be_bytes(authentic_digest_bytes[0..4].try_into().unwrap()),
        u32::from_be_bytes(authentic_digest_bytes[4..8].try_into().unwrap()),
        u32::from_be_bytes(authentic_digest_bytes[8..12].try_into().unwrap()),
        u32::from_be_bytes(authentic_digest_bytes[12..16].try_into().unwrap()),
        u32::from_be_bytes(authentic_digest_bytes[16..20].try_into().unwrap()),
    ];

    for key_len in 0..128 {
        // just bruteforce the padding len - could be calculated
        for padding_len in 0..512 {
            let faked_padding = sha1_padding(key_len + msg.len());
            // calculated the target message
            let mut faked_msg = msg.as_bytes().to_vec();
            faked_msg.extend(&faked_padding);
            faked_msg.extend(attack.as_bytes());

            let mut mm = cryptopals::sha1::Sha1::new_with_state(
                &faked_state,
                (key_len + msg.len() + padding_len) as u64,
            );

            mm.update(attack.to_string().as_bytes());
            let faked_digest = mm.digest();

            let matches = authenticator.verify(&faked_msg, &faked_digest.bytes());
            if matches {
                println!(
                    "!!! found keylen {} paddinglen {} {} {}",
                    key_len,
                    padding_len,
                    String::from_utf8_lossy(&faked_msg),
                    faked_digest.to_string(),
                );
                break;
            }
        }
    }
}
