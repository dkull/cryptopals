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

pub fn pkcs7_padding(data: &mut Vec<u8>, block_size: u8) {
    let missing_bytes = block_size as usize % data.len();
    (0..missing_bytes).for_each(|_| data.push(missing_bytes as u8));
}
#[test]
fn pkcs7_padding_works() {
    let mut case1 = (vec![0x00, 0xff, 0x01], vec![0x00, 0xff], 3);
    pkcs7_padding(&mut case1.1, case1.2);
    assert_eq!(case1.0, case1.1);

    let mut case2 = (
        vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01],
        vec![0x00, 0xff, 0x01, 0x00, 0xff, 0x01, 0x02, 0x02],
        8,
    );
    pkcs7_padding(&mut case1.1, case1.2);
    assert_eq!(case1.0, case1.1);
}
