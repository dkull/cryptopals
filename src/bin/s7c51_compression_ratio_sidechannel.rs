extern crate cryptopals;
extern crate deflate;

use cryptopals::block_ciphers::AESBlockMode;
use deflate::deflate_bytes;

const PADDING: &[u8] = b"!\"#$%&'()*,-./:;<>?@[\\]^_`{|}~";
const CHARSET: &[u8] = b"+/0987654321ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const SESSIONID: &[u8; 54] = b"sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=";
const SESS_LEN: usize = 43;

fn oracle(pt: &[u8], encrypt: bool) -> usize {
    let req_http = vec![
        b"POST / HTTP/1.1
        Host: hapless.com
        Cookie: "
            .to_vec(),
        SESSIONID.to_vec(),
        b"\nContent-Length:".to_vec(),
        pt.len().to_string().as_bytes().to_vec(),
        b"\n".to_vec(),
        pt.to_vec(),
    ]
    .concat();

    let compressed = deflate_bytes(&req_http);

    if !encrypt {
        // part 1 just returned this - no need for cipher
        compressed.len()
    } else {
        // part 2
        let random_key = cryptopals::random_key(16);
        let mut key = [0u8; 16];
        key.copy_from_slice(&random_key);
        let ct = cryptopals::block_ciphers::aes_encrypt(&compressed, &key, None, AESBlockMode::CBC);
        ct.len()
    }
}

fn part2_recursive(i: usize, buffer: Vec<u8>) -> Vec<u8> {
    if buffer[i] == b'=' {
        return buffer;
    }
    let mut buffer = buffer;
    let i_baseline = oracle(&buffer, true);

    println!(
        "=== recurse i: {} baseline: {} buff: {}",
        i,
        i_baseline,
        String::from_utf8_lossy(&buffer)
    );

    // set random data to end until we have a new block
    for padding_byte in CHARSET.iter() {
        for padding_width in 0..2048 {
            let mut padding = Vec::with_capacity(padding_width);
            // adding bytes one by one is crucial to hit the right spot
            // mixing it up a bit allows us to use less padding
            for pw in 0..padding_width {
                if pw % 2 == 0 {
                    padding.push(b'!');
                } else {
                    padding.push(*padding_byte);
                };
            }
            let score = oracle(&vec![buffer.clone(), padding.clone()].concat(), true);

            // not enough entropy
            if score <= i_baseline {
                continue;
            }

            for candidate in CHARSET.iter() {
                buffer[i] = *candidate;
                let oracle_input = vec![buffer.clone(), padding.clone()].concat();
                let ratio = oracle(&oracle_input, true);
                if ratio <= i_baseline {
                    return part2_recursive(i + 1, buffer);
                }
            }
        }
    }

    buffer
}

fn main() {
    eprintln!("(s7c51)");

    //
    // part 1
    //
    let prefix = b"sessionid=";
    let suffix = b"=";
    let mut buffer = vec![prefix.to_vec(), [95u8; SESS_LEN].to_vec(), suffix.to_vec()].concat();
    let mut i = prefix.len();
    loop {
        let mut best_candidate = 0u8;
        let mut best_ratio = 1000000;

        for candidate in CHARSET.iter() {
            buffer[i] = *candidate;
            let ratio = oracle(&buffer, false);
            if ratio < best_ratio {
                best_candidate = *candidate;
                best_ratio = ratio;
            }
        }

        buffer[i] = best_candidate;
        i += 1;

        println!("result: {}", String::from_utf8_lossy(&buffer.clone()));
        if buffer[i] == b'=' {
            break;
        }
    }

    if buffer == SESSIONID {
        println!("Part1 Found!");
    } else {
        println!("Part1 Failed!");
    }

    //
    // part 2
    //

    //
    // this part uses a recursive function to add A LOT of repeating padding to the
    // block, so we can detect the exact moment when a correct character causes 1 less block.
    // basically we drive the compression to the point where it is a bit over
    // the amount needed to not make a new block. only the correct letter can shorten it
    //

    let mut inner_buffer = [0u8; SESS_LEN];
    for c in 0..inner_buffer.len() {
        inner_buffer[c] = PADDING[c % PADDING.len()];
    }
    let buffer = vec![prefix.to_vec(), inner_buffer.to_vec(), suffix.to_vec()].concat();
    let result = part2_recursive(prefix.len(), buffer);
    if result == SESSIONID {
        println!("Part2 Found! {}", String::from_utf8_lossy(&result));
    } else {
        println!("Part2 Failed!");
    }
}
