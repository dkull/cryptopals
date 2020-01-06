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
cargo run --release --bin decrypt_aes_ecb "YELLOW SUBMARINE" < res/s1c7.txt

s1c8 (detect ecb mode from lines)
---
cargo run --release --bin detect_ecb_mode < res/s1c8.txt

s2c9 (pkcs7 padding)
---
created into block_ciphers.rs

s2c10 (decrypt aes-cbc)
---
cargo run --bin decrypt_aes_cbc "YELLOW SUBMARINE" < res/s2c10.txt
