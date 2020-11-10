extern crate cryptopals;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;
use cryptopals::bytes_to_hex;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

const BS: usize = 16;
const HS: usize = 4;

fn md(m: &[u8], h: &[u8; HS]) -> Vec<u8> {
    /*
        my Merkle-Damgard uses h as key, m as message, should be flipped
    */

    let mut padded_h = [0u8; BS];
    padded_h[..HS].copy_from_slice(h);

    for block in m.chunks(HS) {
        let cipher = Aes128::new(GenericArray::from_slice(&padded_h));
        let mut container = [0u8; BS];
        container[..HS].copy_from_slice(&block);
        let mut buffer = GenericArray::clone_from_slice(&container);
        cipher.encrypt_block(&mut buffer);
        padded_h[..HS].copy_from_slice(&buffer[..HS]);
    }

    padded_h[..HS].to_vec()
}

fn find_collision_pair(long_len: usize, h: &[u8; HS]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let dummy_block = [0u8; HS];
    let mut prefix_h = [0u8; HS];
    prefix_h.copy_from_slice(h);

    // build dummy prefix
    let mut prefix: Vec<u8> = Vec::with_capacity((long_len + 1) * HS);
    // don't add the last block
    for _ in 0..long_len - 1 {
        // calc intermediate hash
        let long_hash = &md(&dummy_block, &prefix_h);
        prefix_h.copy_from_slice(long_hash);
        // build dummy
        prefix.extend(&dummy_block);
    }

    let mut long_hashes: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(2usize.pow(20));
    let mut short_hashes: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(2usize.pow(20));

    // find collision
    for block in 0..u32::MAX {
        let block = block.to_be_bytes();
        let short_hash = md(&block, &h);
        let long_hash = md(&block, &prefix_h);

        if let Some(coll_long) = long_hashes.get(&short_hash) {
            prefix.extend(coll_long);
            return (short_hash.to_vec(), block.to_vec(), prefix.to_vec());
        }

        if let Some(coll_short) = short_hashes.get(&long_hash) {
            prefix.extend(&block);
            return (long_hash.to_vec(), coll_short.to_vec(), prefix.to_vec());
        }

        long_hashes.insert(long_hash.to_vec(), block.to_vec());
        short_hashes.insert(short_hash.to_vec(), block.to_vec());
    }
    unreachable!();
}

fn build_expandable_message(k: usize, h: &[u8; HS]) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut h_tmp = [0u8; HS];
    h_tmp.copy_from_slice(h);

    let mut output = Vec::with_capacity(k);
    for i in 0..k {
        // larger blocks first - just more understandable this way
        // also no reverse needed at the end
        let i = k - i - 1;
        let long_len = 2usize.pow(i.try_into().unwrap()) + 1;
        let (hash, short, long) = find_collision_pair(long_len, &h_tmp);
        println!(
            "collision: in_hash: {} ({}, <long>[blocks:{}]) out_hash: {}",
            bytes_to_hex(&h_tmp),
            bytes_to_hex(&short),
            long_len,
            bytes_to_hex(&hash)
        );

        h_tmp.copy_from_slice(&hash);
        output.push((short, long, hash));
    }
    output
}

fn produce_message(expandable_msg: &[(Vec<u8>, Vec<u8>, Vec<u8>)], k: usize, L: usize) -> Vec<u8> {
    assert!(L >= k);

    let mut added_blocks = 0;
    let mut msg = vec![];
    let t = L - k;
    for i in 0..k {
        let long_len = expandable_msg[i].1.len() / HS;
        println!(
            "k: {} i: {} need: {} added: {} -- new long {}",
            k, i, L, added_blocks, long_len
        );
        let mask = 0x01 << (k - i - 1);
        if t & mask >= 1 {
            msg.extend(expandable_msg[i].1.clone());
            added_blocks += long_len;
        } else {
            msg.extend(expandable_msg[i].0.clone());
            added_blocks += 1;
        }
    }
    assert_eq!(added_blocks, L);
    assert_eq!(msg.len() / HS, L);
    msg
}

fn main() {
    //
    // https://www.schneier.com/wp-content/uploads/2016/02/paper-preimages.pdf
    //

    eprintln!("(s7c53)");

    // helper
    let zero_block = [0u8; HS];
    let k = 25; // 20 matches with HS=4

    //
    // find collisions + build expandable message
    //

    let exp_msg = build_expandable_message(k, &zero_block);

    //
    // print info about found pairs
    //

    let mut lookup = HashMap::new();
    let mut last_hash = [0u8; HS];
    for (short, long, hash) in &exp_msg {
        last_hash.copy_from_slice(hash);
        lookup.insert(hash, (short.clone(), long.clone()));
    }
    println!(
        "expandable msg has {} pairs with final hash {}",
        exp_msg.len(),
        bytes_to_hex(&last_hash)
    );

    //
    // attack!
    //

    let target_m = cryptopals::random_key(2usize.pow(k.try_into().unwrap()) * (HS as usize));

    let original_hash = md(&target_m, &zero_block);
    println!(
        "(generated random target m len: {} hash: {})",
        target_m.len() / HS,
        bytes_to_hex(&original_hash)
    );

    // store all intermediate hashes of M
    println!("storing intermediate hashes of M...");

    let mut init_h = [0u8; HS];
    let mut intermediate_hashes = HashMap::with_capacity(target_m.len() / HS);
    for (i, block) in target_m.chunks(HS).enumerate() {
        // block {i} takes in hash {init_h}
        intermediate_hashes.insert(init_h.to_vec(), i);
        let hash = md(&block, &init_h);
        init_h.copy_from_slice(&hash);
    }

    // find the linking block
    println!("searching for linking block...");

    let mut injection_at: Option<usize> = None;
    let mut bridge: Option<Vec<u8>> = None;
    let mut m_tail: Option<Vec<u8>> = None;

    for block in 0..u32::MAX {
        let block = block.to_be_bytes();
        let hash = md(&block, &last_hash);
        if let Some(first_usable) = intermediate_hashes.get(&hash) {
            println!(
                "found: last_hash {} + block {} => hash {}, which matches input hash ({}) of a block at M[{}]",
                bytes_to_hex(&last_hash),
                bytes_to_hex(&block),
                bytes_to_hex(&hash),
                bytes_to_hex(&hash),
                *first_usable,
            );
            injection_at = Some(*first_usable);
            bridge = Some(block.to_vec());
            m_tail = Some(target_m[(first_usable * HS)..].to_vec());
            break;
        }
    }

    // check if we got everything

    let injection_at = injection_at.expect("did not find injection point");
    let bridge = bridge.expect("did not find injection point");
    let m_tail = m_tail.expect("did not find injection point");

    println!("first usable block found at {}", injection_at);

    //
    // produce the prefix message
    //

    let prefix = produce_message(&exp_msg, k, injection_at - 1); // -1 for the linking block
    println!(
        "prefix last block: {}",
        bytes_to_hex(&prefix[prefix.len() - HS..])
    );

    let final_fake_m = vec![prefix, bridge, m_tail].concat();
    let fake_msg_hash = md(&final_fake_m, &zero_block);
    println!(
        "final len: {} diff: {} fake hash: {}",
        final_fake_m.len() / HS,
        (final_fake_m.len() / HS) as isize - (target_m.len() / HS) as isize,
        bytes_to_hex(&fake_msg_hash)
    );

    assert_eq!(fake_msg_hash, original_hash);

    println!("[ injection place ]");
    let mut h = [0u8; HS];
    h.copy_from_slice(&zero_block);
    for (i, block) in final_fake_m.chunks(HS).enumerate() {
        let hash = md(&block, &h);
        if (injection_at - 5 < i) && (i < injection_at + 5) {
            println!(
                "i: {} h: {} block: {} new_h: {}",
                i,
                bytes_to_hex(&h),
                bytes_to_hex(&block),
                bytes_to_hex(&hash)
            );
        }
        h.copy_from_slice(&hash);
    }
}
