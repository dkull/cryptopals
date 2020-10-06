extern crate cryptopals;

use cryptopals::get_timestamp;
use cryptopals::mt19937::Mt19937;

const PT: &str = "FOOBAAAAAAAAAAAAAAAAAAAR";

fn main() {
    // let's use 16 bits instead of 32 (for speed)
    let seed = (get_timestamp().as_secs() as u32) % (u16::MAX as u32);

    // prepend random bytes
    let pt = [
        cryptopals::random_key(rand::random::<u8>()),
        PT.as_bytes().to_vec(),
    ]
    .concat();

    // encrypt the data
    let mut authentic_rng = Mt19937::from_seed(seed);
    let ct = pt
        .iter()
        .map(|x: &u8| *x ^ authentic_rng.extract_number() as u8)
        .collect::<Vec<_>>();
    println!(">> ct: {:?}", ct);

    // use new mt19937 to decrypt the data
    let mut authentic_rng = Mt19937::from_seed(seed);
    let pt: String = ct
        .clone()
        .into_iter()
        .map(|x: u8| x ^ authentic_rng.extract_number() as u8)
        .map(|x: u8| x as char)
        .collect::<String>();
    println!(">> pt: {:?}", pt);

    // try all seeds on the ct and end when candidate pt ends with our known-pt
    for seed_candidate in 0..u32::MAX {
        let mut rng = Mt19937::from_seed(seed_candidate);
        let pt = &((&ct)
            .iter()
            .map(|x: &u8| *x ^ rng.extract_number() as u8)
            .map(|x: u8| x as char)
            .collect::<String>());
        if pt.ends_with(PT) {
            println!("found seed: {}", seed);
            break;
        }
    }

    // TODO: the "password reset token" part seem to be basically identical to what
    // we just did. so not going to do this for now, I may come back to this later
}
