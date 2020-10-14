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

pub struct WeakenedSRPServer {
    N: BigUint,
    g: BigUint,
    k: BigUint,
    users_srp: HashMap<String, UserSRP>,
    attack: bool,
}

impl WeakenedSRPServer {
    pub fn start(
        connstring: String,
        N: BigUint,
        g: BigUint,
        k: BigUint,
        users: HashMap<String, String>,
        attack: bool,
    ) {
        let mut users_srp: HashMap<String, UserSRP> = HashMap::new();
        for (username, password) in users.iter() {
            let srp_params = WeakenedSRPServer::calc_user_srp(&g, &N, password);
            users_srp.insert(username.to_string(), srp_params);
        }
        let server = WeakenedSRPServer {
            N,
            g,
            k,
            users_srp,
            attack,
        };
        thread::spawn(move || {
            let listener = TcpListener::bind(connstring).unwrap();
            for stream in listener.incoming() {
                server.handle_connection(stream.unwrap());
            }
        });
    }

    fn handle_connection(&self, mut stream: TcpStream) {
        let dh = if !self.attack {
            DiffieHellmanState::new(&self.g, &self.N)
        } else {
            let secret = 2.to_biguint().unwrap();
            DiffieHellmanState::new_static(&self.g, &self.N, &secret)
        };

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

        let B = &dh.pubkey;

        let u = rand::thread_rng().gen_biguint_below(&self.N);

        /*
        attack: write faked values
        */

        let payload = if !self.attack {
            vec![
                bytes_to_hexbytes(&user_salt.to_bytes_be()),
                [0x00].to_vec(),
                bytes_to_hexbytes(&B.to_bytes_be()), // B
                [0x00].to_vec(),
                bytes_to_hexbytes(&u.to_bytes_be()), // u
            ]
            .concat()
        } else {
            vec![
                bytes_to_hexbytes(&[0]), // salt
                [0x00].to_vec(),
                bytes_to_hexbytes(&B.to_bytes_be()), // B
                [0x00].to_vec(),
                bytes_to_hexbytes(&[1]), // u
            ]
            .concat()
        };
        stream.write_all(&payload).unwrap();

        /*
        read KEX result from client
        */

        let mut buffer = [0; 1024];
        let read_bytes = stream.read(&mut buffer).unwrap();
        let client_hmac = hexbytes_to_bytes(&buffer[..read_bytes]);

        /*
        mount a brute-force crack attack
        */

        if self.attack {
            for password in ["alpha", "beta", "gamma", "p@55w0rd", "zulu"].iter() {
                /*
                the client sends us his HMAC, let's see if we can find a passwordd
                that generates that HMAC - by doing our side of the calculation with
                v's derived from different passwords
                */

                let fake_u: &[u8] = &[1];
                let fake_salt: &[u8] = &[0];
                let x: &BigUint = &BigUint::from_bytes_be(&Sha256::digest(
                    &vec![fake_salt, &password.as_bytes()].concat(),
                ));
                let v = &self.g.modpow(x, &self.N);

                let S = (&A * v.modpow(&BigUint::from_bytes_be(fake_u), &self.N))
                    .modpow(&dh.secret, &self.N);
                let K: &[u8] = &Sha256::digest(&S.to_bytes_be());
                let guessed_hmac: &[u8] = &Sha256::digest(&vec![K, fake_salt].concat());
                if guessed_hmac == client_hmac {
                    println!("\n!!!!cracked password: {}\n", &password);
                }
            }
        }

        /*
        proceed with our calculations
        */

        let S = (&A * user_v.modpow(&u, &self.N)).modpow(&dh.secret, &self.N);
        let K: &[u8] = &Sha256::digest(&S.to_bytes_be());

        let server_hmac = Sha256::digest(&vec![K, &user_salt.to_bytes_be()].concat());
        if client_hmac == server_hmac.as_slice() {
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

pub struct WeakenedSRPClient {}

impl WeakenedSRPClient {
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
        let mut tokens = data.splitn(3, |x| x == &0x00_u8);

        let server_salt = BigUint::from_bytes_be(&hexbytes_to_bytes(&tokens.next().unwrap()));
        let B = BigUint::from_bytes_be(&hexbytes_to_bytes(&tokens.next().unwrap()));
        let u = BigUint::from_bytes_be(&hexbytes_to_bytes(&tokens.next().unwrap()));

        /*
        compute stuff
        */

        let x = BigUint::from_bytes_be(&Sha256::digest(
            &vec![server_salt.to_bytes_be(), password.as_bytes().to_vec()].concat(),
        ));
        let S = B.modpow(&(dh.secret + (u * x)), &N);

        let K: &[u8] = &Sha256::digest(&S.to_bytes_be());

        /*
        send our HMAC(K, salt) to server for verification
        */

        let hmac: &[u8] = &Sha256::digest(&vec![K, &server_salt.to_bytes_be()].concat());
        stream.write_all(&bytes_to_hexbytes(hmac)).unwrap();

        /*
        read final "OK" or "FAIL"
        */

        let mut buffer = [0_u8; 2048];
        let _ = stream.read(&mut buffer).unwrap();
        buffer[0] == 'O' as u8
    }
}
