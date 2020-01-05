extern crate cryptopals;

fn main() {
    let data = cryptopals::load_stdin();
    eprintln!("(s1c4)");

    let mut best = (-0xff, 0x00, vec![]);
    for line in data.lines() {
        let line = cryptopals::hex_to_bytes(line);
        let (score, key, output) = cryptopals::find_xor_key_eng(&line, 1);
        if score > best.0 && String::from_utf8(output.clone()).is_ok() {
            best = (score, key, output);
        }
    }
    eprintln!("best candidate is {:?}", &best);
    let (_score, _key, bytes) = best;
    let text = String::from_utf8(bytes).expect("result should be text?");
    println!("{}", text);
}
