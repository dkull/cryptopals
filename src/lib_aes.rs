use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Ecb};

type Aes128Ecb = Ecb<Aes128, Pkcs7>;

pub fn decrypt_aes(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let cipher = Aes128Ecb::new_var(&key, &iv).unwrap();
    match cipher.decrypt_vec(&data) {
        Ok(pt) => Ok(pt),
        _ => Err("error".to_string()),
    }
}
