//extern crate cryptopals;
use std::num::Wrapping;

const w: u32 = 32;
const n: u32 = 624;
const m: u32 = 397;
const r: u32 = 31;
const u: Wrapping<u32> = Wrapping(11);
const f: Wrapping<u32> = Wrapping(1812433253);

struct Mt19937 {
    state: [Wrapping<u32>; n as usize],
    index: u32,
}
impl Mt19937 {
    fn from_seed(seed: u32) -> Mt19937 {
        let mut state = [Wrapping(0); n as usize];
        state[0] = Wrapping(seed);
        for i in 1..n as usize {
            state[i] = f * (state[i - 1] ^ (state[i - 1] >> 30)) + Wrapping(i as u32);
        }
        Mt19937 {
            state,
            index: n as u32,
        }
    }

    fn extract_number(&mut self) -> u32 {
        if self.index >= n {
            self.twist();
        }
        let mut y: u32 = self.state[self.index as usize].0;
        y ^= y >> 11;
        y ^= y << 7 & 0x9D2C_5680;
        y ^= y << 15 & 0xEFC6_0000;
        y ^= y >> 18;

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        let upper_mask: Wrapping<u32> = Wrapping(0x8000_0000);
        let lower_mask: Wrapping<u32> = Wrapping(0x7fff_ffff);
        for i in 0..n as usize {
            let x = (self.state[i] & upper_mask) + (self.state[(i + 1) % n as usize] & lower_mask);
            let mut x_a: Wrapping<u32> = x >> 1;
            if x % Wrapping(2) != Wrapping(0) {
                x_a ^= Wrapping(0x9908_B0DF);
            }
            self.state[i] = self.state[(i + m as usize) % n as usize] ^ x_a;
        }
        self.index = 0;
    }
}

#[test]
fn test_mt19937() {
    use std::collections::HashMap;
    // matches output from:
    // http://burtleburtle.net/bob/c/readable.c
    let verification_data: HashMap<usize, u32> = [
        (0, 3331822403),
        (1, 157471482),
        (2, 2805605540),
        (3, 3776487808),
        (4, 3041352379),
        (5, 1684094076),
        (6, 1865610459),
        (7, 4068209049),
        (8, 1179506908),
        (9, 2512518870),
        (10, 3068092408),
        (100, 1155969921),
        (1000, 885714877),
        (9000, 270018718),
        (10000, 725707472),
        (100000, 3292829284),
    ]
    .iter()
    .cloned()
    .collect();

    let largest_test = verification_data.keys().max().expect("need some tests");

    let mut mt = Mt19937::from_seed(0x12345678u32);
    for i in 0..=*largest_test {
        let out_num = mt.extract_number();
        if let Some(verification_num) = verification_data.get(&i) {
            assert_eq!(out_num, *verification_num);
        }
    }
}
