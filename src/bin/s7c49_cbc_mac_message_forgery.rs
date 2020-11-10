extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

const BS: usize = 16;

fn do_cbc_mac(p: &[u8], key: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    let ct = cryptopals::block_ciphers::aes_encrypt(p, key, Some(*iv), AESBlockMode::CBC);
    ct[ct.len() - BS..].to_vec()
}

struct BankServer {
    key: [u8; 16],
}

impl BankServer {
    pub fn new() -> BankServer {
        let random_key = cryptopals::random_key(16 as usize);
        let mut key = [0u8; 16];
        key.copy_from_slice(&random_key);
        BankServer { key }
    }

    //
    // part 1 stuff
    //

    pub fn format_message(from: usize, to: usize, amount: usize) -> Vec<u8> {
        format!("from={:01}&to={:01}&amount={:07}", from, to, amount)
            .as_bytes()
            .to_vec()
    }

    pub fn process_message(&self, signed_order: &[u8]) -> bool {
        let len = signed_order.len();
        let msg = signed_order[0..len - (2 * BS)].to_vec();
        let iv = signed_order[len - (2 * BS)..len - (BS)].to_vec();
        let mac = signed_order[len - BS..].to_vec();
        println!("BANK got msg len: {}", len);
        println!("BANK got msg body: {}", cryptopals::bytes_to_hex(&msg));
        println!("BANK got msg iv: {}", cryptopals::bytes_to_hex(&iv));
        println!("BANK got msg mac: {}", cryptopals::bytes_to_hex(&mac));

        let mut _iv = [0u8; 16];
        _iv.copy_from_slice(&iv);

        let real_mac = do_cbc_mac(&msg, &self.key, &_iv);
        let log_msg = String::from_utf8_lossy(&msg);
        if mac == real_mac {
            println!("BANK: mac verified, doing: {}", log_msg);
            true
        } else {
            println!("BANK: mac verify failed :( {}", log_msg);
            false
        }
    }

    pub fn intercept_message(&self) -> Vec<u8> {
        let msg = BankServer::format_message(1, 2, 1000000);

        let random_iv = cryptopals::random_key(16 as usize);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&random_iv);

        let mac = do_cbc_mac(&msg, &self.key, &iv);

        vec![msg, iv.to_vec(), mac].concat()
    }

    //
    // part 2 stuff
    //

    pub fn format_multi_message(from: usize, txs: Vec<(usize, usize)>) -> Vec<u8> {
        let mut transactions = String::new();
        for (i, (to, amount)) in txs.iter().enumerate() {
            if i > 0 {
                transactions.push(';');
            }
            transactions.push_str(&format!("{}:{}", to, amount));
        }

        format!("from={:01}&tx_list={}", from, transactions)
            .as_bytes()
            .to_vec()
    }

    pub fn process_multi_message(&self, signed_order: &[u8]) -> bool {
        let len = signed_order.len();
        let msg = signed_order[0..len - BS].to_vec();
        let mac = signed_order[len - BS..].to_vec();
        println!("BANK got msg len: {}", len);
        println!("BANK got msg body: {}", cryptopals::bytes_to_hex(&msg));
        println!("BANK got msg mac: {}", cryptopals::bytes_to_hex(&mac));

        let real_mac = do_cbc_mac(&msg, &self.key, &[0u8; 16]);
        let log_msg = String::from_utf8_lossy(&msg);
        if mac == real_mac {
            println!("BANK: mac verified, doing: {}", log_msg);
            true
        } else {
            println!("BANK: mac verify failed :( {}", log_msg);
            false
        }
    }

    pub fn create_multi_message(&self, sender: usize, receiver: usize) -> Vec<u8> {
        // 1337 is attackers account, the attacker can call this function
        let msg =
            BankServer::format_multi_message(sender, vec![(receiver, 1000), (receiver, 1000)]);
        let mac = do_cbc_mac(&msg, &self.key, &[0u8; 16]);
        vec![msg, mac].concat()
    }
}

fn main() {
    eprintln!("(s7c49)");

    let server = BankServer::new();

    //
    // part 1
    //
    println!("=== part 1");

    //
    // intercept a legitimate transfer (1M clams from id:1->id:2)
    //

    let intercepted_msg = server.intercept_message();

    // test the original messages verifies
    assert!(server.process_message(&intercepted_msg));

    //
    // start forging
    //
    println!("= forging");
    let desired_msg = BankServer::format_message(2, 3, 1000000);
    let msg_len = desired_msg.len();

    // calculate the difference between the intercepted and our desired pts
    let pt_diff = cryptopals::xor_arrays(&intercepted_msg[..BS], &desired_msg[..BS]);

    // now apply that difference to the intercepted IV
    let fake_iv = cryptopals::xor_arrays(&intercepted_msg[msg_len..msg_len + BS], &pt_diff);

    // the intercepted mac stays intact, we just insert our desired message and forged iv
    let real_mac = intercepted_msg[intercepted_msg.len() - BS..].to_vec();
    let forged_msg = vec![desired_msg, fake_iv, real_mac].concat();

    assert!(server.process_message(&forged_msg));

    //
    // part 2
    //

    println!("=== part 2");

    let mut vic_msg = server.create_multi_message(11, 22);
    assert!(server.process_multi_message(&vic_msg));
    let vic_mac = vic_msg.split_off(vic_msg.len() - BS);

    println!("= forging");

    cryptopals::block_ciphers::pkcs7_padding(&mut vic_msg, BS);

    let mut attack_msg = server.create_multi_message(22, 33);
    let attack_mac = attack_msg.split_off(attack_msg.len() - BS);
    let attack_payload = attack_msg.split_off(BS);

    let attack_msg = cryptopals::xor_arrays(&attack_msg, &vic_mac);
    let forged_msg = vec![vic_msg, attack_msg, attack_payload, attack_mac].concat();

    assert!(server.process_multi_message(&forged_msg));
}
