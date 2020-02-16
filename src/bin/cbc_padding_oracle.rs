extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

const BLOCK_SIZE: usize = 16;

fn load_and_test_input(
    pt_lines: std::str::Lines,
    oracle: &Oracle,
    iv: &[u8; 16],
    key: &[u8],
) -> Vec<Vec<u8>> {
    pt_lines
        .map(|pt_line| {
            // foo
            let raw_line = cryptopals::base64_to_bytes(pt_line);
            let ct = cryptopals::block_ciphers::aes_encrypt(
                &raw_line,
                &key,
                Some(*iv),
                AESBlockMode::CBC,
            );
            println!(
                "test_raw_line {} -> {}",
                String::from_utf8_lossy(&raw_line),
                cryptopals::bytes_to_hex(&ct)
            );
            let padding_ok = oracle.padding_ok(&ct);
            assert!(padding_ok);
            ct
        })
        .collect::<Vec<Vec<u8>>>()
}

struct Oracle {
    iv: [u8; 16],
    key: [u8; 16],
}

impl Oracle {
    pub fn new(iv: [u8; 16], key: [u8; 16]) -> Oracle {
        Oracle { iv, key }
    }
    pub fn padding_ok(&self, data: &[u8]) -> bool {
        let result = cryptopals::block_ciphers::aes_decrypt(
            data,
            &self.key[..],
            Some(self.iv),
            AESBlockMode::CBC,
        );
        !result.is_empty()
    }
}

fn attack(oracle: &Oracle, ct: &[u8]) -> Vec<u8> {
    let chunks = ct.chunks(16);
    println!("ct: {}", cryptopals::bytes_to_hex(ct));
    println!("blocks: {}", chunks.len());
    let mut attack_result_bytes = vec![];

    let input_ct = ct.to_vec();

    for i in (0..chunks.len() - 1).rev() {
        // since we tweak the ct, we need a fresh copy for each block
        let mut ct = input_ct.to_vec();
        for b in (0..BLOCK_SIZE).rev() {
            let mut found_hit = false;
            let change_at = (i * BLOCK_SIZE) + b;
            let target_value = (BLOCK_SIZE - b) as u8;
            /*
            println!(
                "tweaking block {} byte {} ({}) to change block {} byte {} pt value to {}",
                i,
                b,
                ct[b],
                i + 1,
                b,
                target_value
            );
            */
            let mut data = ct.to_vec();
            let mut shift = false;
            let mut saved_t = 0;
            for t in 0..=255 {
                if t == ct[change_at] {
                    shift = true;
                    saved_t = t;
                }
                // save the possible single hit for last
                let t = if t == 255 {
                    saved_t
                } else if shift {
                    t + 1
                } else {
                    t
                };

                data[change_at] = t;
                let padding_ok = oracle.padding_ok(&data[0..BLOCK_SIZE * (i + 2)]);
                if padding_ok {
                    found_hit = true;
                    let pt_byte = ct[change_at] ^ t ^ target_value;
                    let block_output = ct[change_at] ^ pt_byte;
                    /*
                    println!(
                        "ok with {}=>{} (was {}) pt={}^{}^{}={} block out {}^{}={}",
                        t,
                        target_value,
                        ct[change_at],
                        t,
                        ct[change_at],
                        target_value,
                        pt_byte,
                        ct[change_at],
                        pt_byte,
                        block_output,
                    );
                    */
                    // increment all tailing bytes by 1
                    for increment_byte in change_at..(i + 1) * BLOCK_SIZE {
                        let t = data[increment_byte];
                        let incremented = t ^ target_value ^ (target_value + 1);
                        /*
                        println!(
                            "changed byte at {} to {}^{}^{}=>{}",
                            increment_byte,
                            t,
                            target_value,
                            target_value + 1,
                            incremented
                        );
                        */
                        // increment all tailing bytes by 1
                        ct[increment_byte] = incremented;
                    }
                    attack_result_bytes.push(pt_byte);
                    break;
                }
            }
            if !found_hit {
                println!("did not find hit!");
                break;
            }
        }
    }
    attack_result_bytes.into_iter().rev().collect::<Vec<_>>()
}

fn main() {
    eprintln!("(s3c17)");
    let data = &cryptopals::load_stdin();
    let random_key = cryptopals::random_key(16);
    let random_iv = cryptopals::random_key(16);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&random_iv);
    let mut key = [0u8; 16];
    key.copy_from_slice(&random_key);

    let oracle = Oracle::new(iv, key);

    let pt_lines = data.lines();
    let ct_lines = load_and_test_input(pt_lines, &oracle, &iv, &random_key);

    println!("\nstart padding oracle attack on iv+ct...");
    ct_lines.iter().for_each(|ct| {
        println!("---");
        let result = attack(&oracle, &ct);
        println!("attack result: {}", String::from_utf8_lossy(&result));
    });
}
