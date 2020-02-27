extern crate cryptopals;

use cryptopals::get_timestamp;

// this is to speed up the brute force search, let's NOT search
// all the timestamps since the epoch
// 1.5B is 2017-07-14T
const START_SECONDS: u64 = 1_500_000_000;

fn main() {
    println!("(s3c22)");
    /*
        The challenge really wants us to wait for the results, so let's unnecessarily brute force it :)
    */
    let seed = get_timestamp().as_secs() as u64;
    println!("seeding the rng [secret: {}]", seed);
    let mut mt = cryptopals::mt19937::Mt19937::from_seed(seed as u32);

    let random_value = mt.extract_number();
    println!("got random value: {}", random_value);

    // obiously the answer is the current value of get_timestamp()
    for i in START_SECONDS..=get_timestamp().as_secs() as u64 {
        let mut mt = cryptopals::mt19937::Mt19937::from_seed(i as u32);
        if i % 1_000_000 == 0 {
            println!("checking seed {}", i);
        }
        if mt.extract_number() == random_value {
            let now = get_timestamp().as_secs() as u64;
            println!(
                "found number to be from seed: {}, this is {}s ago",
                i,
                now - i
            );
            break;
        }
    }
}
