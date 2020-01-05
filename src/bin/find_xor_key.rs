extern crate cryptopals;

use std::env;

fn main() {
    eprintln!("(s1c6)");
    let data = cryptopals::base64_to_bytes(&cryptopals::load_stdin());

    let max_len = &env::args().collect::<Vec<_>>()[1]
        .parse()
        .expect("first argument has to be number");
    eprintln!(
        "trying for keys up to length '{}' inner data first bytes {:x?}",
        max_len,
        &data[0..10]
    );

    let mut best_result = (-0xffff, vec![], vec![]);

    for try_length in 1..=*max_len {
        let (best_score, best_key, best_output) = cryptopals::search_xor_key(&data, try_length);
        if best_score > best_result.0 {
            best_result = (best_score, best_key, best_output);
        }
    }

    let readable_result = String::from_utf8(best_result.2.clone()).unwrap();
    println!(
        "best key {:x?} with output:\n{}",
        best_result.1, readable_result
    );
}
