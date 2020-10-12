#![allow(non_snake_case)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use sha2::{Digest, Sha256};

use crate::dh::DiffieHellmanState;
use crate::{bytes_to_hexbytes, hexbytes_to_bytes};

struct UserSRP {
    v: BigUint,
    salt: BigUint,
}

pub struct SRPServer {
    N: BigUint,
    g: BigUint,
    k: BigUint,
    users_srp: HashMap<String, UserSRP>,
}

impl SRPServer {
    pub fn start(
        connstring: String,
        N: BigUint,
        g: BigUint,
        k: BigUint,
        users: HashMap<String, String>,
    ) {
        let mut users_srp: HashMap<String, UserSRP> = HashMap::new();
        for (username, password) in users.iter() {
            let srp_params = SRPServer::calc_user_srp(&g, &N, password);
            users_srp.insert(username.to_string(), srp_params);
        }
        let server = SRPServer { N, g, k, users_srp };
        thread::spawn(move || {
            let listener = TcpListener::bind(connstring).unwrap();
            for stream in listener.incoming() {
                server.handle_connection(stream.unwrap());
            }
        });
    }

    fn handle_connection(&self, mut stream: TcpStream) {
        let dh = DiffieHellmanState::new(&self.g, &self.N);
        /*
        read username+DH_pubkey
        */
        let mut buffer = [0; 1024];
        let read_bytes = stream.read(&mut buffer).unwrap();
        let data = buffer[..read_bytes].to_vec();
        let mut tokens = data.splitn(2, |x| x == &0x00_u8);

        let username = String::from_utf8(tokens.next().unwrap().to_vec()).unwrap();
        let A = BigUint::from_bytes_be(&hexbytes_to_bytes(&tokens.next().unwrap()));

        let user_srp = self.users_srp.get(&username).unwrap();
        let user_v = &user_srp.v;
        let user_salt = &user_srp.salt;

        let B = (&self.k * user_v) + dh.pubkey;
        /*
        write salt+B as response
        */
        stream
            .write_all(
                &vec![
                    bytes_to_hexbytes(&user_salt.to_bytes_be()),
                    [0x00].to_vec(),
                    bytes_to_hexbytes(&B.to_bytes_be()),
                ]
                .concat(),
            )
            .unwrap();
        /*
        proceed with our calculations
        */
        let u = BigUint::from_bytes_be(&Sha256::digest(
            &vec![A.to_bytes_be(), B.to_bytes_be()].concat(),
        ));

        let S = (A * user_v.modpow(&u, &self.N)).modpow(&dh.secret, &self.N);
        let K: &[u8] = &Sha256::digest(&S.to_bytes_be());

        let etalon = Sha256::digest(&vec![K, &user_salt.to_bytes_be()].concat());
        /*
        read KEX result from client
        */
        let mut buffer = [0; 1024];
        let read_bytes = stream.read(&mut buffer).unwrap();
        let payload = &buffer[..read_bytes];

        if hexbytes_to_bytes(payload) == etalon.as_slice() {
            stream.write_all(b"OK").unwrap();
        } else {
            stream.write_all(b"FAIL").unwrap();
        }
    }

    fn calc_user_srp(g: &BigUint, N: &BigUint, password: &str) -> UserSRP {
        let salt = rand::thread_rng().gen_biguint_below(N);

        let mut hasher = Sha256::new();
        hasher.update(salt.to_bytes_be());
        hasher.update(password);

        let x = BigUint::from_bytes_be(&hasher.finalize());
        let v = g.modpow(&x, N);

        UserSRP { v, salt }
    }
}

pub struct SRPClient {}

impl SRPClient {
    pub fn auth(
        connstring: String,
        N: BigUint,
        g: BigUint,
        k: BigUint,
        username: String,
        password: String,
    ) -> bool {
        let mut stream = TcpStream::connect(connstring).unwrap();

        /*
        send username and DH pubkey
        */
        let dh = DiffieHellmanState::new(&g, &N);
        let A = dh.pubkey;
        stream
            .write_all(
                &vec![
                    username.as_bytes(),
                    &[0x00],
                    &bytes_to_hexbytes(&A.to_bytes_be()),
                ]
                .concat(),
            )
            .unwrap();

        /*
        read salt+B from server
        */
        let mut buffer = [0; 2048];
        let read_bytes = stream.read(&mut buffer).unwrap();

        let data = buffer[..read_bytes].to_vec();
        let mut tokens = data.splitn(2, |x| x == &0x00_u8);

        let server_salt = BigUint::from_bytes_be(&hexbytes_to_bytes(&tokens.next().unwrap()));
        let B = BigUint::from_bytes_be(&hexbytes_to_bytes(&tokens.next().unwrap()));

        /*
        compute stuff
        */
        let u = BigUint::from_bytes_be(&Sha256::digest(
            &vec![A.to_bytes_be(), B.to_bytes_be()].concat(),
        ));

        let x = BigUint::from_bytes_be(&Sha256::digest(
            &vec![server_salt.to_bytes_be(), password.as_bytes().to_vec()].concat(),
        ));
        let S = (B - (k * (g.modpow(&x, &N)))).modpow(&(dh.secret + (u * x)), &N);

        let K = Sha256::digest(&S.to_bytes_be());

        /*
        send our HMAC(K, salt) to server for verification
        */
        let mut hasher = Sha256::new();
        hasher.update(K);
        hasher.update(server_salt.to_bytes_be());
        let hmac = hasher.finalize();
        stream.write_all(&bytes_to_hexbytes(&hmac)).unwrap();

        /*
        read final "OK" or "FAIL"
        */
        let mut buffer = [0_u8; 2048];
        let _ = stream.read(&mut buffer).unwrap();
        if buffer[0] == 'O' as u8 {
            true
        } else {
            false
        }
    }
}
