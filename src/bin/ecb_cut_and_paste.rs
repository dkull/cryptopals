extern crate cryptopals;

use std::collections::HashMap;
use std::iter::FromIterator;

use cryptopals::block_ciphers::AESBlockMode;

struct Login {
    key: Vec<u8>,
}

impl Login {
    fn new() -> Login {
        Login {
            key: cryptopals::random_key(16),
        }
    }
    fn parse_cookie(&self, data: &str) -> HashMap<String, String> {
        let parsed = data
            .split('&')
            .map(|pair| {
                let tokens = pair.split('=').collect::<Vec<_>>();
                (tokens[0].to_string(), tokens[1].to_string())
            })
            .collect::<Vec<_>>();
        HashMap::from_iter(parsed)
    }

    pub fn login_admin(&self, data: &[u8]) -> bool {
        let pt = cryptopals::block_ciphers::aes_decrypt(&data, &self.key, None, AESBlockMode::ECB);
        match String::from_utf8(pt) {
            Ok(pt) => match self.parse_cookie(&pt).get("role") {
                Some(val) => val == "admin",
                None => false,
            },
            _ => false,
        }
    }

    pub fn create_user_account(&self, email: &str) -> Vec<u8> {
        let sanitized_email = email.replace('&', "x").replace('=', "x");
        let pt_cookie = format!("email={}&uid=10&role=user", sanitized_email)
            .bytes()
            .collect::<Vec<_>>();
        cryptopals::block_ciphers::aes_encrypt(&pt_cookie, &self.key, None, AESBlockMode::ECB)
    }
}

/*
    goal:
    email=foo@bar.com&uid=10&role=admin
    have:
    email=foo@bar.com&uid=10&role=user
    =>
    p1                p2                p3                p4
    [email=hello@bar.][com&uid=10&role=][admin&uid=10&rol][le=user]
*/
fn main() {
    eprintln!("(s2c13)");

    let login = Login::new();

    let ct1 = login.create_user_account("hello@bar.com");
    let p1 = ct1[0..16].to_vec();
    let p2 = ct1[16..32].to_vec();

    let ct2 = login.create_user_account("hello@bar.admin");
    let p3 = ct2[16..32].to_vec();

    let ct3 = login.create_user_account("helllo@bar.admin");
    let p4 = ct3[32..48].to_vec();

    let hacked_cookie = vec![p1, p2, p3, p4].concat();

    let success = login.login_admin(&hacked_cookie);
    println!("admin login? {}", success);
}
