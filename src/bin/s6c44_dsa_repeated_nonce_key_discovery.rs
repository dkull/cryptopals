extern crate cryptopals;

use cryptopals::dsa::DSA;
use cryptopals::sha1::Sha1;
use std::io::Read;

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, ToBigUint};

pub fn main() {
    /*
    authentic verifier we are trying to fool
    */

    let msg = b"ATTACK AT DAWN";
    let msg_bn = BigInt::from_signed_bytes_be(msg);

    let dsa = DSA::new();
    let sig = dsa.sign(&msg_bn);
    let verified = dsa.verify(&msg_bn, &sig.0, &sig.1);

    println!("selftest: {}", verified);

    /*
    attack
    */

    let data = vec![
        (
            BigInt::from_signed_bytes_be(b"Listen for me, you better listen for me now. "),
            BigInt::parse_bytes(b"1267396447369736888040262262183731677867615804316", 10).unwrap(),
            BigInt::parse_bytes(b"1105520928110492191417703162650245113664610474875", 10).unwrap(),
            BigInt::parse_bytes(b"a4db3de27e2db3e5ef085ced2bced91b82e0df19", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"Listen for me, you better listen for me now. "),
            BigInt::parse_bytes(b"29097472083055673620219739525237952924429516683", 10).unwrap(),
            BigInt::parse_bytes(b"51241962016175933742870323080382366896234169532", 10).unwrap(),
            BigInt::parse_bytes(b"a4db3de27e2db3e5ef085ced2bced91b82e0df19", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"When me rockin' the microphone me rock on steady, "),
            BigInt::parse_bytes(b"277954141006005142760672187124679727147013405915", 10).unwrap(),
            BigInt::parse_bytes(b"228998983350752111397582948403934722619745721541", 10).unwrap(),
            BigInt::parse_bytes(b"21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"Yes a Daddy me Snow me are de article dan. "),
            BigInt::parse_bytes(b"1013310051748123261520038320957902085950122277350", 10).unwrap(),
            BigInt::parse_bytes(b"1099349585689717635654222811555852075108857446485", 10).unwrap(),
            BigInt::parse_bytes(b"1d7aaaa05d2dee2f7dabdc6fa70b6ddab9c051c5", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"But in a in an' a out de dance em "),
            BigInt::parse_bytes(b"203941148183364719753516612269608665183595279549", 10).unwrap(),
            BigInt::parse_bytes(b"425320991325990345751346113277224109611205133736", 10).unwrap(),
            BigInt::parse_bytes(b"6bc188db6e9e6c7d796f7fdd7fa411776d7a9ff", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"Aye say where you come from a, "),
            BigInt::parse_bytes(b"502033987625712840101435170279955665681605114553", 10).unwrap(),
            BigInt::parse_bytes(b"486260321619055468276539425880393574698069264007", 10).unwrap(),
            BigInt::parse_bytes(b"5ff4d4e8be2f8aae8a5bfaabf7408bd7628f43c9", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"People em say ya come from Jamaica, "),
            BigInt::parse_bytes(b"1133410958677785175751131958546453870649059955513", 10).unwrap(),
            BigInt::parse_bytes(b"537050122560927032962561247064393639163940220795", 10).unwrap(),
            BigInt::parse_bytes(b"7d9abd18bbecdaa93650ecc4da1b9fcae911412", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(
                b"But me born an' raised in the ghetto that I want yas to know, ",
            ),
            BigInt::parse_bytes(b"559339368782867010304266546527989050544914568162", 10).unwrap(),
            BigInt::parse_bytes(b"826843595826780327326695197394862356805575316699", 10).unwrap(),
            BigInt::parse_bytes(b"88b9e184393408b133efef59fcef85576d69e249", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"Pure black people mon is all I mon know. "),
            BigInt::parse_bytes(b"1021643638653719618255840562522049391608552714967", 10).unwrap(),
            BigInt::parse_bytes(b"1105520928110492191417703162650245113664610474875", 10).unwrap(),
            BigInt::parse_bytes(b"d22804c4899b522b23eda34d2137cd8cc22b9ce8", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(
                b"Yeah me shoes a an tear up an' now me toes is a show a ",
            ),
            BigInt::parse_bytes(b"506591325247687166499867321330657300306462367256", 10).unwrap(),
            BigInt::parse_bytes(b"51241962016175933742870323080382366896234169532", 10).unwrap(),
            BigInt::parse_bytes(b"bc7ec371d951977cba10381da08fe934dea80314", 16).unwrap(),
        ),
        (
            BigInt::from_signed_bytes_be(b"Where me a born in are de one Toronto, so "),
            BigInt::parse_bytes(b"458429062067186207052865988429747640462282138703", 10).unwrap(),
            BigInt::parse_bytes(b"228998983350752111397582948403934722619745721541", 10).unwrap(),
            BigInt::parse_bytes(b"d6340bfcda59b6b75b59ca634813d572de800e8f", 16).unwrap(),
        ),
    ];

    let given_pubkey = BigInt::parse_bytes(
        b"2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
        13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
        5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
        f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
        f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
        2971c3de5084cce04a2e147821",
        16,
    )
    .unwrap();

    for (i, msg_a) in data.iter().enumerate() {
        for (j, msg_b) in data.iter().enumerate() {
            if j <= i {
                continue;
            }
            let mut above = (&msg_a.3 - &msg_b.3) % &dsa.q;
            if above < 0.to_bigint().unwrap() {
                above = &dsa.q + above;
            }

            let mut below = (&msg_a.1 - &msg_b.1) % &dsa.q;
            if below < 0.to_bigint().unwrap() {
                below = &dsa.q + below;
            }

            let maybe_k = (&above * DSA::mod_inv(&below, &dsa.q).unwrap()) % &dsa.q;
            println!("a: {} b: {} k: {:x}", i, j, maybe_k);

            /* let's do a shortcut and just compare the extracted private_key to the one
            given in the task */
            let mut privkey_guess = ((&msg_a.1 * &maybe_k) - &msg_a.3)
                * DSA::mod_inv(&msg_a.2, &dsa.q).unwrap()
                % &dsa.q;
            if privkey_guess < 0.to_bigint().unwrap() {
                privkey_guess = &dsa.g + privkey_guess;
            }

            let pubkey_guess = &dsa.g.modpow(&privkey_guess, &dsa.p);

            if pubkey_guess == &given_pubkey {
                println!(
                    "found messages {} and {} using same k {} using privkey {:x}",
                    i, j, maybe_k, privkey_guess
                );
            }
        }
    }
}
