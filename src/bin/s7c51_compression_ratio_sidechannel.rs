extern crate cryptopals;
extern crate deflate;

use cryptopals::block_ciphers::AESBlockMode;
use deflate::deflate_bytes;

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

fn main() {
    eprintln!("(s7c51)");
    let charset = b"+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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

        for candidate in charset.iter() {
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
    let mut buffer = vec![prefix.to_vec(), [95u8; SESS_LEN].to_vec(), suffix.to_vec()].concat();
    let mut i = prefix.len();
    loop {
        let mut best_candidate = 0u8;
        let mut best_ratio = 1000000;

        for candidate in charset.iter() {
            buffer[i] = *candidate;

            // part2 magic
            let oracle_input = vec![
                buffer[..i + 1].to_vec(),
                buffer[..buffer.len() - i - 1].to_vec(),
            ]
            .to_vec()
            .concat();

            let ratio = oracle(&oracle_input, false);
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
        println!("Part2 Found!");
    } else {
        println!("Part2 Failed!");
    }
}
