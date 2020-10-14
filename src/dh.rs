use num_bigint::{BigUint, RandBigInt};

pub struct DiffieHellmanState {
    pub secret: BigUint,
    p: BigUint,
    g: BigUint,
    pub pubkey: BigUint,
}

impl DiffieHellmanState {
    pub fn new(g: &BigUint, p: &BigUint) -> DiffieHellmanState {
        let secret = rand::thread_rng().gen_biguint_below(&p);
        let pubkey = DiffieHellmanState::gen_pubkey(&p, &g, &secret);
        DiffieHellmanState {
            secret,
            p: p.clone(),
            g: g.clone(),
            pubkey,
        }
    }

    pub fn new_static(g: &BigUint, p: &BigUint, secret: &BigUint) -> DiffieHellmanState {
        let pubkey = DiffieHellmanState::gen_pubkey(&p, &g, &secret);
        DiffieHellmanState {
            secret: secret.clone(),
            p: p.clone(),
            g: g.clone(),
            pubkey,
        }
    }

    pub fn gen_shared_key(self, other_pubkey: &BigUint) -> BigUint {
        other_pubkey.modpow(&self.secret, &self.p)
    }

    fn gen_pubkey(p: &BigUint, g: &BigUint, secret: &BigUint) -> BigUint {
        g.modpow(secret, p)
    }
}
