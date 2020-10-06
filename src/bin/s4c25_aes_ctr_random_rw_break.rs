extern crate cryptopals;

use cryptopals::block_ciphers::AESBlockMode;

struct Api {
    key: Vec<u8>,
}

impl Api {
    fn dec(&self, ct: &[u8]) -> Vec<u8> {
        cryptopals::block_ciphers::aes_decrypt(ct, &self.key, None, AESBlockMode::CTR)
    }

    fn enc(&self, pt: &[u8]) -> Vec<u8> {
        cryptopals::block_ciphers::aes_encrypt(pt, &self.key, None, AESBlockMode::CTR)
    }

    pub fn edit_api_call(&self, ct: &[u8], offset: usize, new_text: &[u8]) -> Vec<u8> {
        // decrypt all of CT -
        // decrypting just the one block would be much more cumbersome to implement
        let mut pt = self.dec(ct);

        // replace the ct at offset - what could go wrong
        pt.splice(offset.., new_text.to_vec()).for_each(drop);

        // re-encrypt the modified pt
        self.enc(&pt)
    }
}

fn main() {
    println!("(s4c25)\n");

    let data = cryptopals::load_stdin();
    let key = cryptopals::random_key(16);

    let secret_data =
        cryptopals::block_ciphers::aes_encrypt(&data.as_bytes(), &key[..], None, AESBlockMode::CTR);

    let api = Api { key };

    // replace whole text with the encrypted form of itself - this will get
    // xored with the key blocks - which will return us the original PT
    let res = api.edit_api_call(&secret_data, 0, &secret_data);
    println!("recovered: {}", String::from_utf8_lossy(&res));
}
