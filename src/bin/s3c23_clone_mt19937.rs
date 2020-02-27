extern crate cryptopals;

use std::num::Wrapping;

use cryptopals::get_timestamp;
use cryptopals::mt19937::Mt19937;

const n: usize = 624;

fn main() {
    let seed = get_timestamp().as_secs() as u32;
    let mut authentic_rng = Mt19937::from_seed(seed);

    let mut cloned_state = [Wrapping(0); n];
    for x in cloned_state.iter_mut() {
        let rng_value = authentic_rng.extract_number();
        let untempered_value = authentic_rng.untemper(rng_value);
        *x = Wrapping(untempered_value);
    }

    let mut cloned_rng = Mt19937::from_state(cloned_state, n as u32);

    println!(
        "authentic next: {} cloned next: {}",
        authentic_rng.extract_number(),
        cloned_rng.extract_number()
    );
}
