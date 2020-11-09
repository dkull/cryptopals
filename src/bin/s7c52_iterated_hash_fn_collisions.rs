extern crate cryptopals;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;
use cryptopals::bytes_to_hex;
use std::collections::HashMap;

const BS: usize = 16;
const HS: usize = 4;

fn md(m: &[u8], h: &[u8; HS]) -> Vec<u8> {
    let mut m = m.to_vec();
    while m.len() % HS != 0 {
        m.push(0);
    }

    let mut padded_h = [0u8; BS];
    padded_h[..HS].copy_from_slice(h);

    for block in m.chunks(HS) {
        let cipher = Aes128::new(GenericArray::from_slice(&padded_h));
        let mut container = [7u8; BS];
        container[..HS].copy_from_slice(&block);
        let mut buffer = GenericArray::clone_from_slice(&container);
        cipher.encrypt_block(&mut buffer);
        padded_h[..HS].copy_from_slice(&buffer[..HS]);
    }

    padded_h[..HS].to_vec()
}

fn main() {
    eprintln!("(s7c52)");

    //
    // The paper at https://www.isical.ac.in/~mridul/Papers/thesis/thesis.pdf
    // was very helpful. Section 5.2.
    // Also https://www.iacr.org/archive/crypto2004/31520306/multicollisions.pdf
    //
    // default hasher takes zero_block as h,
    // we use a different hasher by just passing one_block as initial h.
    //

    // helpers
    let zero_block = [0u8; HS];
    let one_block = [1u8; HS];

    // store total md() count
    let mut calculations = 0;

    println!("=== part 1");

    //
    // find successive collisions
    //

    let find_n_collisions = 16;

    println!(
        "finding {} {} bytesequential collisions in func#1 with initial_h: {}",
        find_n_collisions,
        HS,
        bytes_to_hex(&zero_block)
    );

    let mut h = [0u8; HS];
    let mut seen: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)> = HashMap::new();
    let mut chains: Vec<Vec<u8>> = vec![];
    let expect_collisions = 2u32.pow(find_n_collisions) as usize;
    let mut collisions = 0;
    for m_alt in 0..u32::MAX {
        let m = m_alt.to_be_bytes();
        let orig_hash = &h.clone();
        let hash = md(&m, &h);
        calculations += 1;
        if let Some((prev_m, prev_m_hash)) = seen.get(&hash) {
            // duplicate all existing elements
            // and append new block
            if chains.is_empty() {
                chains.push(m.to_vec());
                chains.push(prev_m.clone());
            } else {
                let old_chains = chains.clone();
                chains.clear();
                for oc in old_chains {
                    let mut a = oc.clone();
                    let mut b = oc.clone();
                    a.extend(&m);
                    b.extend(prev_m.clone());
                    chains.push(a);
                    chains.push(b);
                }
            }
            collisions = chains.len();

            h.copy_from_slice(&hash);
            println!(
                "hash {} is m:{}<-h:{} prev_m:{}<-h:{} [hashes: {}]",
                bytes_to_hex(&hash),
                bytes_to_hex(&m),
                bytes_to_hex(orig_hash),
                bytes_to_hex(&prev_m),
                bytes_to_hex(&prev_m_hash),
                seen.len()
            );
            seen.clear();
        }
        seen.insert(hash.clone(), (m.to_vec(), orig_hash.to_vec()));
        if collisions == expect_collisions {
            break;
        }
    }
    println!("brute-force computed {} hashes", calculations);
    println!(
        "built {} colliding inputs from {} sequential collisions",
        chains.len(),
        find_n_collisions
    );

    /* // uncomment to see all collision
    for chain in &chains {
        let chain_hash = md(&chain, &zero_block);
        println!("{} -> {}", bytes_to_hex(&chain), bytes_to_hex(&chain_hash));
    }*/

    //
    // part 2
    //

    println!("=== part 2");

    // find collision in found chains
    let mut seen: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    for chain in &chains {
        let hash = md(&chain, &one_block);
        calculations += 1;
        if let Some(existing_data) = seen.get(&hash) {
            println!(
                "found collision in func#2: init_h: {} h: {} in \ndata_1: {} \ndata_2: {}",
                bytes_to_hex(&one_block),
                bytes_to_hex(&hash),
                bytes_to_hex(&chain),
                bytes_to_hex(&existing_data)
            );
            break;
        }
        seen.insert(hash, chain.clone());
    }

    println!("called md() a total of {} times", calculations);
}
