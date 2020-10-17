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

s2c11 (cbs vs ecb oracle)
---
cargo run --bin oracle_cbc_ecb

s2c12 (byte-a-time ecb decrypt simple)
---
cargo run --release --bin break_ecb_byte_simple < res/s2c12.txt

s2c13 (ecb cut and paste cookie)
---
cargo run --bin ecb_cut_and_paste

s2c14 (byte-a-time ecb decrypt harder)
---
cargo run --release --bin break_ecb_byte_harder < res/s2c12.txt

s2c16 (cbc bitlipping attack)
---
cargo run --bin cbc_bitflipping

s3c17 (cbc padding oracle)
---
# FIXME: I do not decrypt the first block, add a virtual empty block before the first one?
cargo run --bin cbc_padding_oracle < res/s3c17.txt

s3c18 (ctr mode)
---
created into block_ciphers.rs

s3c19 (ctr break substitutions - dumb)
---
cargo run --bin break_ctr_dumb < res/s3c19.txt

s3c20 (ctr break sattistic - smart) actually same as previous
---
cargo run --bin break_ctr_smart < res/s3c20.txt

s3c21 (mt19937)
---
implemented into lib under mt19937.rs

s3c22 (mt19937 epoch seed crack)
---
cargo run --release --bin s3c22_mt19937_wait_crack

s3c23 (mt19937 clone from output)
---
cargo run --release --bin s3c23_clone_mt19937

s3c24 (mt19937 stream cipher + crack)
---
`cargo run --release --bin s3c24_mt19937_cipher`

s4c25 (aes_ctr_random_rw_break)
---
`cargo run --release --bin s4c25_aes_ctr_random_rw_break < res/s4c25.txt`

s4c26
---
`cargo run --release --bin s4c26_ctr_bitflipping`

s4c27
---
`cargo run --release --bin s4c27_cbc_break_key_as_iv`

s4c29 (sha1 keyed mac break)
---
I created a new method "new_with_state" in sha1.rs
`cargo run --release --bin s4c29_sha1_keyed_mac_break`

s4c30 (md4 keyed mac break)
---
`cargo run --release --bin s4c30_md4_keyed_mac_break`

s4c31 && s4c32 (break byte-by-byte comparing HMAC API)
---
This solution does backtracking and multiple tries per byte.
I can brute-force HMAC's with 1ms delay on localhost. Didn't try lower.
`cargo run --bin s4c31_sha1_keyed_mac_timing_break`

s5c33 (implement Diffie Hellman)
---
`cargo run --bin s5c33_impl_diffie_hellman`

s5c34 (Diffie Hellman Key Fixing MITM)
---
`cargo run --bin s5c34_dh_key_fixing_mitm`

s5c35 (Diffie Hellman negotiated group MITM)
---
`cargo run --bin s5c35_dh_negotiated_groups_mitm`

s5c36 (SRP Client+Server)
---
New library file srp.rs
`cargo run --bin s5c36_srp_client_server`

s5c37 (SRP Zero key break)
---
`cargo run --bin s5c37_srp_zero_key_break`

s5c38 (Weakened SRP offline dictionary attack)
---
`cargo run --bin s5c38_weakened_srp_offline_attack`

s5c39/s5c40 (RSA and E=3 broadcast attack)
---
`cargo run --bin s5c40_rsa_e3_broadcast_attack`

s6c41 (RSA unpadded message oracle)
---
`cargo run --bin s6c41_rsa_unpadded_oracle`

s6c42 (RSA Bleichenbacher signature forge)
---
`cargo run --bin s6c42_rsa_bleichenbacher_signature_forge`

s6c43 (DSA + DSA nonce key recovery)
---
`cargo run --release --bin s6c43_dsa_nonce_key_discovery`
