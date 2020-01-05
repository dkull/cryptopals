# cryptopals
Solving the Cryptopals.com challenges

s1c1-s1c3
---
implemented in lib.rs as functions (with tests)

s1c4
---
cargo run --bin detect_singlechar_xor < res/s1c4.txt

s1c5
---
cargo run --bin xor_encrypt ICE < res/s1c5.txt

s1c6 (find xor key)
---
cargo run --release --bin find_xor_key 30 < res/s1c6.txt

s1c7 (decrypt aes-ecb)
---
cargo run --release --bin decrypt_aes "YELLOW SUBMARINE" < res/s1c7.txt
