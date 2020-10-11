extern crate byteorder;
extern crate cryptopals;

use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process;
use std::time::Instant;
use std::{thread, time};

const SECRET_KEY: &str = "very_secret_hmac_key";
const SLEEP_TIME: u64 = 1;
const TARGET_FILE: &str = "secret_aliens.txt";
const TRIES_PER_BYTE: usize = 3;
const CONNSTRING: &str = "127.0.0.1:7878";

fn handle_connection(mut stream: TcpStream) {
    let sleep_time = time::Duration::from_millis(SLEEP_TIME);
    let mut buffer = [0; 1024];

    let read_nr_bytes = stream.read(&mut buffer).unwrap();

    let request_body = String::from_utf8(buffer.to_vec()).unwrap();
    let mut tokens = request_body[..read_nr_bytes].split('|');

    let filename = tokens.next().unwrap();
    let hmac = cryptopals::hex_to_bytes(tokens.next().unwrap());

    let mut hasher = cryptopals::sha1::Sha1::new();
    hasher.update(&SECRET_KEY.to_string().as_bytes());
    hasher.update(filename.to_string().as_bytes());

    let digest_bytes = hasher.digest().bytes();

    println!(
        "SERVER: Request: file: {} hmac: {} | expecting: {}",
        filename,
        cryptopals::bytes_to_hex(&hmac),
        cryptopals::bytes_to_hex(&digest_bytes)
    );

    for (i, input) in digest_bytes.iter().enumerate() {
        let is_equal = input == &hmac[i];
        // sleep after every comparison
        thread::sleep(sleep_time);

        if !is_equal {
            stream.write_all("ERROR!".to_string().as_bytes()).unwrap();
            return;
        }
    }
    println!("HMAC matches - nice!");
    stream.write_all("OK!".to_string().as_bytes()).unwrap();
}

fn main() {
    // spawn a server
    thread::spawn(move || {
        let listener = TcpListener::bind(CONNSTRING).unwrap();
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            handle_connection(stream);
        }
    });
    // wait for the server to start up
    thread::sleep(time::Duration::from_millis(50));

    // store "known" bytes of the HMAC
    let mut known_hmac: Vec<u8> = vec![];

    // store fastest timing for every HMAC byte position - this allows backtracking
    let mut fastest_timings = [0u128; 20];
    loop {
        // timings for every byte candidate for a specific HMAC byte position
        let mut timings = vec![0xFFFFFFFFFFFFFFFF_u128; 0xFF + 1];

        // test all candidates
        for candidate in 0x00_u8..=0xFF_u8 {
            // properly formatted candidate HMAC - zero padded
            let long_candidate = format!(
                "{:0<40}",
                format!(
                    "{}{:02.x}",
                    cryptopals::bytes_to_hex(&known_hmac),
                    candidate
                )
            );

            // try X times per byte - to get the smallest time taken
            for _ in 0..TRIES_PER_BYTE {
                let mut buf = [0; 128];
                let mut socket = TcpStream::connect(CONNSTRING).unwrap();

                let now = Instant::now();
                socket
                    .write_all(&format!("{}|{}", TARGET_FILE, long_candidate).as_bytes())
                    .unwrap();

                if let Ok(i) = socket.read(&mut buf) {
                    let resp = String::from_utf8_lossy(&buf[..i]);
                    if resp.contains("OK!") {
                        println!("read OK response byts: {} => {:?}", i, resp);
                        process::exit(0);
                    }
                    let delay = now.elapsed().as_micros();
                    // if this try was faster, record the time
                    if delay < timings[candidate as usize] {
                        timings[candidate as usize] = delay;
                    }
                } else {
                    println!("connection error");
                    process::exit(1);
                }
            }
        }

        // find the slowest byte for this position - this is likely the correct byte
        let slowest_byte = timings
            .iter()
            .enumerate()
            .fold((0, 0), |acc, (i, x)| if x > &acc.1 { (i, *x) } else { acc })
            .0;

        let fastest_time = timings.iter().min().unwrap();
        let known_bytes = known_hmac.len();

        // my fastest needs to be faster than last byte fastest
        let fastest_time_per_byte = *fastest_time as f64 / known_bytes as f64;
        let prev_fastest_time_per_byte = if known_bytes == 0 {
            0_f64
        } else {
            fastest_timings[known_bytes - 1] as f64 / known_bytes as f64
        };
        // only proceed if this position was slower than the previous one, else backtrack
        if known_bytes == 0 || fastest_time_per_byte > prev_fastest_time_per_byte {
            known_hmac.push(slowest_byte as u8);
            // mark fastest time for current HMAC byte position
            fastest_timings[known_bytes] = *fastest_time;
        } else {
            // if we didn't go slower for this byte we probably got the previous byte
            // wrong - backtrack
            known_hmac.pop();
        }
    }
}
