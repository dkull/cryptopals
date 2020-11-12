extern crate cryptopals;

use cryptopals::bytes_to_hex;
use std::collections::HashMap;

const OBSERVE_INDEX: usize = 32;

struct RC4 {
    s: [u8; 256],
    i: usize,
    j: usize,
}

impl RC4 {
    fn new(key: &[u8]) -> RC4 {
        let mut data = [0u8; 256];
        for i in 0..u8::MAX {
            data[i as usize] = i as u8;
        }

        let mut j: u32 = 0;
        for i in 0..256 {
            j = (j + data[i] as u32 + key[i % key.len()] as u32) % 256;
            let a = data[i as usize];
            let b = data[j as usize];
            data[i as usize] = b;
            data[j as usize] = a;
        }

        RC4 {
            s: data,
            i: 0,
            j: 0,
        }
    }

    fn get_byte(&mut self) -> u8 {
        self.i = (self.i + 1) % 256;
        self.j = (self.j + self.s[self.i] as usize) as usize % 256;

        let a = self.s[self.i];
        let b = self.s[self.j];
        self.s[self.i] = b;
        self.s[self.j] = a;

        let idx = (self.s[self.i] as usize + self.s[self.j] as usize) % 256;

        self.s[idx as usize]
    }
}

fn request(path: &[u8]) -> Vec<u8> {
    let key = cryptopals::random_key(32 as usize);
    let mut rc4 = RC4::new(&key);

    let cookie = cryptopals::base64_to_bytes("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F");

    let p = vec![b"/".to_vec(), path.to_vec(), cookie.to_vec()].concat();
    let mut c = vec![];

    for pc in p {
        c.push(rc4.get_byte() ^ pc);
    }

    c
}

pub fn main() {
    let path_char = 64u8;
    let helper = [path_char; OBSERVE_INDEX - 1]; // set secret to 32th
    let mut bias_map = HashMap::new();

    let mut i = 0;
    loop {
        let ct = request(&helper[i..]);
        if ct.len() <= OBSERVE_INDEX {
            break;
        }

        bias_map.clear();
        for i in 0..=u8::MAX {
            bias_map.insert(i, 0);
        }
        for _ in 0..50_000 {
            let ct = request(&helper[i..]);
            let observe = ct[OBSERVE_INDEX];
            let cnt = bias_map.get(&observe).unwrap();
            bias_map.insert(observe, cnt + 1);
        }

        let mut kvs = bias_map.iter().map(|x| (x.1, x.0)).collect::<Vec<_>>();
        kvs.sort();

        let last = kvs.last().unwrap();
        println!("{:?} -> {} ", last.1, *last.1 as char);
        i += 1;
    }
}
