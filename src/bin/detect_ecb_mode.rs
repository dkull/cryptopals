extern crate cryptopals;

const BLOCK_SIZE: usize = 16;

fn main() {
    eprintln!("(s1c8)");
    let data = &cryptopals::load_stdin();

    let mut best_guess = (0, vec![]);

    for line in data.lines() {
        let line = cryptopals::hex_to_bytes(line);
        let blocks = line.chunks(BLOCK_SIZE).collect::<Vec<_>>();
        let mut similar = 0;
        for (i, a) in blocks.iter().enumerate() {
            for (j, b) in blocks.iter().enumerate() {
                if j < i || a != b {
                    continue;
                }
                similar += 1;
            }
        }
        if similar > best_guess.0 {
            best_guess = (similar, line);
        }
    }
    println!(
        "best guess: matching blocks {} for line {:x?}",
        best_guess.0, best_guess.1
    );
}
