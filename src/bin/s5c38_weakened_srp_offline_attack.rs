extern crate cryptopals;

use std::collections::HashMap;
use std::{thread, time};

use num_bigint::{BigUint, ToBigUint};

pub fn main() {
    let N = BigUint::parse_bytes(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
    fffffffffffff"
            .to_string()
            .as_bytes(),
        16,
    )
    .unwrap();
    let username = "admin".to_string();
    let password = "p@55w0rd".to_string();
    let connstring = "localhost:7878".to_string();
    let connstring2 = "localhost:7979".to_string();

    let mut users: HashMap<String, String> = HashMap::new();
    users.insert(username.clone(), password.clone());

    cryptopals::weakened_srp::WeakenedSRPServer::start(
        connstring.clone(),
        N.clone(),
        2_usize.to_biguint().unwrap(),
        3_usize.to_biguint().unwrap(),
        users.clone(),
        false,
    );

    let sleep_time = time::Duration::from_millis(100);
    thread::sleep(sleep_time);

    println!("=== Normal auth");
    let authenticated = cryptopals::weakened_srp::WeakenedSRPClient::auth(
        connstring.clone(),
        N.clone(),
        2_usize.to_biguint().unwrap(),
        3_usize.to_biguint().unwrap(),
        username.clone(),
        password.clone(),
    );
    println!("authed as \"{}\": {}", &username, authenticated);

    println!("=== Bad auth (wrong password)");
    /*
    let's override A and hardcode S to be 0
    */
    let authenticated = cryptopals::weakened_srp::WeakenedSRPClient::auth(
        connstring.clone(),
        N.clone(),
        2_usize.to_biguint().unwrap(),
        3_usize.to_biguint().unwrap(),
        username.clone(),
        "wrong_password".to_string(),
    );
    println!("authed as \"{}\" : {}", username, authenticated);

    /*
    let's start another server instance - evil this time
    */

    println!("=== Starting attack server");
    cryptopals::weakened_srp::WeakenedSRPServer::start(
        connstring2.clone(),
        N.clone(),
        2_usize.to_biguint().unwrap(),
        3_usize.to_biguint().unwrap(),
        users,
        true,
    );
    thread::sleep(sleep_time);

    /*
    let's override A and hardcode S to be 0
    */
    let authenticated = cryptopals::weakened_srp::WeakenedSRPClient::auth(
        connstring2.clone(),
        N.clone(),
        2_usize.to_biguint().unwrap(),
        3_usize.to_biguint().unwrap(),
        username.clone(),
        password,
    );
    println!("authed as \"{}\" : {}", username, authenticated);
}
