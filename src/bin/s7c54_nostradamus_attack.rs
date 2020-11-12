extern crate cryptopals;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;
use cryptopals::bytes_to_hex;
use std::collections::HashMap;

const BS: usize = 16;
const HS: usize = 4;

fn md(m: &[u8], h: &[u8; HS]) -> Vec<u8> {
    let mut padded_h = [0u8; BS];
    padded_h[..HS].copy_from_slice(h);

    for block in m.chunks(HS) {
        let mut key = [0u8; BS];
        key[..HS].copy_from_slice(block);
        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut container = [0u8; BS];
        container[..BS].copy_from_slice(&padded_h);
        let mut buffer = GenericArray::clone_from_slice(&container);
        cipher.encrypt_block(&mut buffer);
        padded_h[..HS].copy_from_slice(&buffer[..HS]);
    }

    padded_h[..HS].to_vec()
}

struct Layer {
    pub nodes: HashMap<Vec<u8>, Vec<u8>>,
    pub out_hashes: Vec<Vec<u8>>,
}

fn find_collision_pair(h1: &[u8; HS], h2: &[u8; HS]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut hashes1: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(2usize.pow(20));
    let mut hashes2: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(2usize.pow(20));

    // find collision
    for msg_block in 0..u32::MAX {
        let msg_block = msg_block.to_be_bytes();
        let hash1 = md(&msg_block, &h1);
        let hash2 = md(&msg_block, &h2);

        if let Some(msg1) = hashes1.get(&hash2) {
            return (msg1.to_vec(), msg_block.to_vec(), hash2.clone());
        }
        if let Some(msg2) = hashes2.get(&hash1) {
            return (msg_block.to_vec(), msg2.to_vec(), hash1.clone());
        }

        hashes1.insert(hash1, msg_block.to_vec());
        hashes2.insert(hash2, msg_block.to_vec());
    }
    unreachable!();
}

fn build_first_layer(k: u32) -> Layer {
    let zeros = [0u8; HS];
    let top_need = 2usize.pow(k) / 2; // div 2 b/c we create two nodes per collision

    let mut layer: Layer = Layer {
        nodes: HashMap::with_capacity(top_need),
        out_hashes: vec![],
    };

    let mut collection: HashMap<Vec<u8>, Vec<u8>> = HashMap::with_capacity(top_need);
    let mut added = 0;
    for in_hash in 0..u32::MAX {
        let in_hash = in_hash.to_be_bytes();
        let out_hash = md(&zeros, &in_hash);
        if let Some(other_in_hash) = collection.get(&out_hash) {
            added += 1;
            println!(
                "now have m: <zeros> + in_h1: {} / in_h2: {} => out_h: {}",
                bytes_to_hex(&in_hash),
                bytes_to_hex(&other_in_hash),
                bytes_to_hex(&out_hash),
            );
            layer.nodes.insert(in_hash.to_vec(), zeros.to_vec());
            layer.nodes.insert(other_in_hash.clone(), zeros.to_vec());
            layer.out_hashes.push(out_hash.clone());

            collection.remove(&out_hash);
        } else {
            collection.insert(out_hash, in_hash.to_vec());
        }
        if added == top_need {
            break;
        }
    }
    println!("first layer done with {} nodes", layer.nodes.len());
    layer
}

fn build_layer(prev_layer: &Layer) -> Layer {
    let mut layer: Layer = Layer {
        nodes: HashMap::with_capacity(prev_layer.nodes.len() / 2),
        out_hashes: vec![],
    };
    for (i, hashes) in prev_layer.out_hashes.chunks(2).enumerate() {
        let mut a_hash = [0u8; HS];
        a_hash.copy_from_slice(&hashes[0]);
        let mut b_hash = [0u8; HS];
        b_hash.copy_from_slice(&hashes[1]);

        if i % 10 == 0 {
            println!(
                "finding collision {}/{}",
                i + 1,
                prev_layer.out_hashes.len() / 2
            );
        }

        let (coll_msg_1, coll_msg_2, coll_hash) = find_collision_pair(&a_hash, &b_hash);
        layer.nodes.insert(a_hash.to_vec(), coll_msg_1);
        layer.nodes.insert(b_hash.to_vec(), coll_msg_2);
        layer.out_hashes.push(coll_hash.clone());
    }
    layer
}

fn build_diamond(k: u32, depth: u32) -> Vec<Layer> {
    println!("building diamond depth: {}", depth);
    if depth == k {
        return vec![build_first_layer(k)];
    }

    let mut layers = build_diamond(k, depth + 1);

    let prev_layer = layers.last().unwrap();
    if prev_layer.out_hashes.len() == 1 {
        return layers;
    }

    let new_layer = build_layer(&prev_layer);
    println!(
        "diamond layer {} done with {} nodes",
        depth,
        new_layer.nodes.len()
    );
    layers.push(new_layer);
    layers
}

fn deeper(diamond: &[Layer], hash: &[u8; HS]) -> Option<Vec<u8>> {
    if diamond.is_empty() {
        return Some(vec![]);
    }
    let first_layer = diamond.first().unwrap();
    if let Some(_coll_msg) = first_layer.nodes.get(&hash[..]) {
        let mut coll_msg = [0u8; HS];
        coll_msg.copy_from_slice(_coll_msg);

        let mut new_hash = [0u8; HS];
        new_hash.copy_from_slice(&md(&coll_msg, &hash));

        let res = deeper(&diamond[1..], &new_hash);
        Some(vec![_coll_msg.clone(), res.unwrap()].concat())
    } else {
        None
    }
}

fn build_message(prefix: &[u8], diamond: &[Layer]) -> Vec<u8> {
    println!(
        "building message for prefix with layer having {} nodes",
        diamond.len()
    );
    let zero_block = [0u8; HS];

    let mut prefix_block = [0u8; HS];
    prefix_block[..prefix.len()].copy_from_slice(prefix);

    let mut prefix_hash = [0u8; HS];
    prefix_hash.copy_from_slice(&md(&prefix_block, &zero_block));

    for link_block in 0..u32::MAX {
        let link_block = link_block.to_be_bytes();

        let mut hash = [0u8; HS];
        hash.copy_from_slice(&md(&link_block, &prefix_hash));

        if let Some(msg) = deeper(&diamond, &hash) {
            println!("link {} found!", bytes_to_hex(&link_block));
            return vec![prefix, &link_block, &msg].concat();
        }
    }
    unreachable!();
}

fn main() {
    //
    // https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=150629
    //

    eprintln!("(s7c54)");

    // helper
    let zero_block = [0u8; HS];
    let k = 9; // we don't need more nodes on a 32bit hash with 2 layers unusable

    let diamond = build_diamond(k as u32, 0 as u32);
    println!(
        "== Final hash: {} supports msgs of block len: {}",
        bytes_to_hex(&diamond.last().unwrap().out_hashes[0]),
        diamond.len()
    );

    println!("== Testing ==");

    for prefix in &["FOOZ", "BLOO"] {
        // we can't use 1st and 2nd layer, as they will be msg+link
        // our MD does not check for padding/length, but we can assume it will work
        let drop_blocks = 2;

        let forged_msg = build_message(prefix.as_bytes(), &diamond[drop_blocks..]);
        let hash_of_forgery = md(&forged_msg, &zero_block);
        println!(
            "== Forgery {} hash: {} msg blocks: {}",
            prefix,
            bytes_to_hex(&hash_of_forgery),
            forged_msg.len() / HS
        );
    }
}
